/**
 * Telegram Lumina Bot
 *
 * A Telegram bot that accepts binary files from users and pushes their
 * symbol information to the Hex-Rays Lumina server.
 *
 * Features:
 *   - Accepts any binary file (ELF, PE, Mach-O, etc.)
 *   - Supports separate PDB file upload for PE binaries
 *   - Queue system for processing multiple submissions
 *   - Real-time progress updates to users
 *   - DWARF debug info extraction when available
 */

#include <td/telegram/Client.h>
#include <td/telegram/td_api.h>
#include <td/telegram/td_api.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// Save real functions before IDA SDK redefines them with macros
static inline int real_setenv(const char* name, const char* value) {
#ifdef _WIN32
    return _putenv_s(name, value);
#else
    return setenv(name, value, 1);
#endif
}

static inline const char* real_getenv(const char* name) {
    return getenv(name);
}

// Save condition_variable::wait before IDA redefines it
#include <condition_variable>
namespace std_cv {
    template<typename Lock, typename Pred>
    void cv_wait(std::condition_variable& cv, Lock& lock, Pred pred) {
        while (!pred()) {
            cv.wait(lock);
        }
    }
}

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>

// Save functions before IDA SDK redefines them with macros
static inline pid_t real_waitpid(pid_t pid, int* status, int options) {
    return waitpid(pid, status, options);
}

static inline char* real_fgets(char* s, int size, FILE* stream) {
    return fgets(s, size, stream);
}

static inline FILE* real_popen(const char* command, const char* type) {
    return popen(command, type);
}

static inline int real_pclose(FILE* stream) {
    return pclose(stream);
}
#endif

// From noplugins.c - controls plugin blocking
extern "C" bool g_block_plugins;

// IDA SDK Headers
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <loader.hpp>
#include <hexrays.hpp>
#include <idalib.hpp>
#include <segment.hpp>
#include <dbg.hpp>
#include <typeinf.hpp>

namespace td_api = td::td_api;
namespace fs = std::filesystem;

//=============================================================================
// Global Configuration
//=============================================================================

struct BotConfig {
    std::string api_id;
    std::string api_hash;
    std::string bot_token;
    std::string work_dir = "/tmp/lumina_bot";
    std::string tdlib_dir = "tdlib_bot";
    std::string ida_lumina_path = "./ida_lumina";  // Path to ida_lumina tool
    size_t max_file_size = 100 * 1024 * 1024;  // 100 MB
    bool no_plugins = true;  // Disable user plugins by default
};

static BotConfig g_config;

//=============================================================================
// Lumina Interface (from lumina.cpp)
//=============================================================================

constexpr size_t LUMINA_VTABLE_PUSH_METADATA = 0x50;

using GetServerConnection2Fn = void* (*)(uint64_t mode);
using PushMetadataFn = uint8_t (*)(void* self, void* output, void* input, void* error_out, uint64_t arg4, uint64_t arg5);

struct PushStats {
    size_t total = 0;
    size_t skip = 0;
    size_t new_count = 0;
    size_t exists = 0;
    size_t error = 0;
};

class LuminaConnection {
private:
    void* m_connection = nullptr;
    void* m_vtable = nullptr;
    GetServerConnection2Fn m_get_server_connection2 = nullptr;
    void* m_libida = nullptr;

    void* get_push_metadata_method() {
        if (!m_vtable) return nullptr;
        void** vtable = static_cast<void**>(m_vtable);
        return vtable[LUMINA_VTABLE_PUSH_METADATA / sizeof(void*)];
    }

public:
    LuminaConnection() {
        m_libida = dlopen("libida.so", RTLD_NOW | RTLD_NOLOAD);
        if (!m_libida) {
            m_libida = dlopen(nullptr, RTLD_NOW);
        }

        if (!m_libida) {
            throw std::runtime_error("Failed to get libida.so handle");
        }

        m_get_server_connection2 = reinterpret_cast<GetServerConnection2Fn>(
            dlsym(m_libida, "get_server_connection2")
        );

        if (!m_get_server_connection2) {
            throw std::runtime_error("Failed to find get_server_connection2");
        }
    }

    bool connect(uint64_t mode = 0) {
        m_connection = m_get_server_connection2(mode);
        if (!m_connection) {
            return false;
        }
        m_vtable = *static_cast<void**>(m_connection);
        return m_vtable != nullptr;
    }

    bool is_connected() const {
        return m_connection != nullptr && m_vtable != nullptr;
    }

    bool push_all(PushStats& stats) {
        if (!is_connected()) {
            return false;
        }

        void* push_method = get_push_metadata_method();
        if (!push_method) {
            return false;
        }

        auto push_fn = reinterpret_cast<PushMetadataFn>(push_method);

        struct {
            void* ptr;
            uint64_t field1;
            uint64_t field2;
            int64_t sentinel;
        } input = { nullptr, 0, 0, -1 };

        struct {
            void* ea_array;
            uint64_t count;
            uint64_t reserved;
            void* result_array;
            uint8_t padding[64];
        } output = {};

        struct {
            void* str_ptr;
            void* has_error;
            uint64_t reserved;
        } error_out = {};

        uint8_t result = push_fn(m_connection, &output, &input, &error_out, 0, 0);

        stats.total = static_cast<size_t>(output.count);

        if (stats.total > 0 && output.ea_array && output.result_array) {
            auto* results = static_cast<uint32_t*>(output.result_array);

            for (size_t i = 0; i < stats.total; i++) {
                uint32_t code = results[i];
                switch (code) {
                    case 0: stats.skip++; break;
                    case 1: stats.new_count++; break;
                    case 2: stats.exists++; break;
                    default: stats.error++; break;
                }
            }
        }

        return result != 0;
    }
};

//=============================================================================
// Job Queue
//=============================================================================

enum class JobStatus {
    PENDING,
    DOWNLOADING,
    QUEUED,
    ANALYZING,
    CONNECTING_LUMINA,
    PUSHING,
    COMPLETED,
    FAILED
};

std::string status_to_string(JobStatus status) {
    switch (status) {
        case JobStatus::PENDING: return "Pending";
        case JobStatus::DOWNLOADING: return "Downloading file...";
        case JobStatus::QUEUED: return "Queued for analysis";
        case JobStatus::ANALYZING: return "Analyzing binary...";
        case JobStatus::CONNECTING_LUMINA: return "Connecting to Lumina...";
        case JobStatus::PUSHING: return "Pushing to Lumina...";
        case JobStatus::COMPLETED: return "Completed";
        case JobStatus::FAILED: return "Failed";
    }
    return "Unknown";
}

std::string status_emoji(JobStatus status) {
    switch (status) {
        case JobStatus::PENDING: return "\xE2\x8F\xB3";        // hourglass
        case JobStatus::DOWNLOADING: return "\xE2\xAC\x87\xEF\xB8\x8F"; // down arrow
        case JobStatus::QUEUED: return "\xF0\x9F\x93\x8B";     // clipboard
        case JobStatus::ANALYZING: return "\xF0\x9F\x94\x8D";  // magnifier
        case JobStatus::CONNECTING_LUMINA: return "\xF0\x9F\x94\x97"; // link
        case JobStatus::PUSHING: return "\xF0\x9F\x9A\x80";    // rocket
        case JobStatus::COMPLETED: return "\xE2\x9C\x85";      // check mark
        case JobStatus::FAILED: return "\xE2\x9D\x8C";         // X mark
    }
    return "";
}

// Escape special characters for Telegram MarkdownV2
std::string escape_markdown(const std::string& text) {
    std::string result;
    result.reserve(text.size() * 2);
    for (char c : text) {
        // Characters that must be escaped in MarkdownV2
        if (c == '_' || c == '*' || c == '[' || c == ']' || c == '(' || c == ')' ||
            c == '~' || c == '`' || c == '>' || c == '#' || c == '+' || c == '-' ||
            c == '=' || c == '|' || c == '{' || c == '}' || c == '.' || c == '!') {
            result += '\\';
        }
        result += c;
    }
    return result;
}

// Generate a hash string from job_id for filename anonymization
static std::string hash_job_id(int64_t job_id) {
    // Simple hash using job_id - produces 16 hex chars
    uint64_t hash = static_cast<uint64_t>(job_id);
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    hash *= 0xc4ceb9fe1a85ec53ULL;
    hash ^= hash >> 33;

    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    return ss.str();
}

// Extract file extension (lowercase)
static std::string get_extension(const std::string& filename) {
    size_t dot = filename.rfind('.');
    if (dot == std::string::npos || dot == filename.length() - 1) {
        return "";
    }
    std::string ext = filename.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext;
}

struct AnalysisJob {
    int64_t job_id;
    int64_t chat_id;
    int64_t message_id;
    int64_t status_message_id = 0;
    std::string file_name;      // Original filename (for display only)
    std::string file_hash;      // Hash used for actual file storage
    std::string local_path;
    std::string pdb_path;       // Optional PDB file for PE binaries
    std::string tdlib_doc_path; // Path to tdlib downloaded doc (for cleanup)
    std::string tdlib_pdb_path; // Path to tdlib downloaded PDB (for cleanup)
    JobStatus status = JobStatus::PENDING;
    std::string error_message;
    size_t function_count = 0;
    PushStats push_stats;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;

    // For tracking file downloads
    int32_t file_id = 0;
    bool waiting_for_pdb = false;
};

class JobQueue {
public:
    int64_t add_job(int64_t chat_id, int64_t message_id, const std::string& file_name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto job = std::make_shared<AnalysisJob>();
        job->job_id = ++m_next_job_id;
        job->chat_id = chat_id;
        job->message_id = message_id;
        job->file_name = file_name;
        job->file_hash = hash_job_id(job->job_id);
        job->created_at = std::chrono::steady_clock::now();
        m_jobs[job->job_id] = job;
        return job->job_id;
    }

    void enqueue(int64_t job_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_jobs.find(job_id);
        if (it != m_jobs.end()) {
            it->second->status = JobStatus::QUEUED;
            m_pending_queue.push_back(job_id);
            m_cv.notify_one();
        }
    }

    std::shared_ptr<AnalysisJob> get_job(int64_t job_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_jobs.find(job_id);
        return (it != m_jobs.end()) ? it->second : nullptr;
    }

    std::shared_ptr<AnalysisJob> find_job_by_status_message(int64_t chat_id, int64_t status_message_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [id, job] : m_jobs) {
            if (job->chat_id == chat_id && job->status_message_id == status_message_id) {
                return job;
            }
        }
        return nullptr;
    }

    std::shared_ptr<AnalysisJob> find_job_by_message(int64_t chat_id, int64_t message_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [id, job] : m_jobs) {
            // Check both the original file message and status message IDs
            if (job->chat_id == chat_id &&
                (job->message_id == message_id || job->status_message_id == message_id)) {
                return job;
            }
        }
        return nullptr;
    }

    std::shared_ptr<AnalysisJob> find_job_waiting_for_pdb(int64_t chat_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [id, job] : m_jobs) {
            if (job->chat_id == chat_id && job->waiting_for_pdb) {
                return job;
            }
        }
        return nullptr;
    }

    std::shared_ptr<AnalysisJob> wait_for_job() {
        std::unique_lock<std::mutex> lock(m_mutex);
        std_cv::cv_wait(m_cv, lock, [this] { return !m_pending_queue.empty() || m_shutdown; });

        if (m_shutdown || m_pending_queue.empty()) {
            return nullptr;
        }

        int64_t job_id = m_pending_queue.front();
        m_pending_queue.pop_front();

        auto it = m_jobs.find(job_id);
        return (it != m_jobs.end()) ? it->second : nullptr;
    }

    void update_status(int64_t job_id, JobStatus status, const std::string& error = "") {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_jobs.find(job_id);
        if (it != m_jobs.end()) {
            it->second->status = status;
            if (!error.empty()) {
                it->second->error_message = error;
            }
            if (status == JobStatus::ANALYZING) {
                it->second->started_at = std::chrono::steady_clock::now();
            }
            if (status == JobStatus::COMPLETED || status == JobStatus::FAILED) {
                it->second->completed_at = std::chrono::steady_clock::now();
            }
        }
    }

    void remove_job(int64_t job_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_jobs.find(job_id);
        if (it != m_jobs.end()) {
            // Clean up work directory files
            std::error_code ec;
            if (!it->second->local_path.empty()) {
                fs::remove(it->second->local_path, ec);
            }
            if (!it->second->pdb_path.empty()) {
                fs::remove(it->second->pdb_path, ec);
            }
            // Clean up tdlib downloaded documents
            if (!it->second->tdlib_doc_path.empty()) {
                fs::remove(it->second->tdlib_doc_path, ec);
            }
            if (!it->second->tdlib_pdb_path.empty()) {
                fs::remove(it->second->tdlib_pdb_path, ec);
            }
            m_jobs.erase(it);
        }
    }

    void shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
        m_cv.notify_all();
    }

    size_t queue_size() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pending_queue.size();
    }

    // For iterating jobs (caller must hold lock)
    std::mutex& get_mutex() { return m_mutex; }
    std::map<int64_t, std::shared_ptr<AnalysisJob>>& get_jobs() { return m_jobs; }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::map<int64_t, std::shared_ptr<AnalysisJob>> m_jobs;
    std::deque<int64_t> m_pending_queue;
    int64_t m_next_job_id = 0;
    bool m_shutdown = false;
};

//=============================================================================
// IDA Analysis Worker
//=============================================================================

hexdsp_t *hexdsp = nullptr;

class AnalysisWorker {
public:
    using StatusCallback = std::function<void(int64_t job_id, JobStatus status, const std::string& detail)>;

    AnalysisWorker(JobQueue& queue, StatusCallback callback)
        : m_queue(queue), m_status_callback(callback) {}

    void start(int num_workers = 5) {
        for (int i = 0; i < num_workers; i++) {
            m_threads.emplace_back(&AnalysisWorker::worker_loop, this, i);
        }
    }

    void stop() {
        m_running = false;
        m_queue.shutdown();
        for (auto& t : m_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

private:
    void worker_loop(int worker_id) {
        std::cout << "[Worker " << worker_id << "] Started" << std::endl;

        while (m_running) {
            auto job = m_queue.wait_for_job();
            if (!job) {
                continue;
            }

            std::cout << "[Worker " << worker_id << "] Processing job " << job->job_id << ": " << job->file_name << std::endl;
            process_job_in_subprocess(job);
            std::cout << "[Worker " << worker_id << "] Job " << job->job_id << " finished" << std::endl;
        }
        std::cout << "[Worker " << worker_id << "] Exiting" << std::endl;
    }

    void process_job_in_subprocess(std::shared_ptr<AnalysisJob> job) {
        m_status_callback(job->job_id, JobStatus::ANALYZING, "");

        // Build command to run ida_lumina as a separate process
        // This avoids fork() issues with multi-threaded TDLib
        std::string cmd = g_config.ida_lumina_path;
        if (g_config.no_plugins) {
            cmd += " --no-plugins";
        }
        cmd += " \"" + job->local_path + "\" 2>&1";

        std::cout << "[Worker] Running: " << cmd << std::endl;

        FILE* pipe = real_popen(cmd.c_str(), "r");
        if (!pipe) {
            job->error_message = "Failed to launch ida_lumina";
            m_status_callback(job->job_id, JobStatus::FAILED, job->error_message);
            return;
        }

        // Read and parse output
        std::string output;
        char buffer[256];
        while (real_fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            output += buffer;
            std::cout << "[ida_lumina] " << buffer;
        }

        int exit_code = real_pclose(pipe);
        bool success = (WIFEXITED(exit_code) && WEXITSTATUS(exit_code) == 0);

        // Parse stats from output
        PushStats stats = {};
        parse_lumina_output(output, stats);

        if (success) {
            job->push_stats = stats;
            job->function_count = stats.total;
            m_status_callback(job->job_id, JobStatus::COMPLETED, "");
        } else {
            // Try to extract error message
            std::string error_msg;
            size_t pos = output.find("[FATAL]");
            if (pos != std::string::npos) {
                size_t end = output.find('\n', pos);
                error_msg = output.substr(pos + 8, end - pos - 8);
            } else if (output.find("Failed to connect to Lumina") != std::string::npos) {
                error_msg = "Failed to connect to Lumina server";
            } else {
                error_msg = "Analysis failed (exit code " + std::to_string(WEXITSTATUS(exit_code)) + ")";
            }
            job->error_message = error_msg;
            m_status_callback(job->job_id, JobStatus::FAILED, error_msg);
        }
    }

    void parse_lumina_output(const std::string& output, PushStats& stats) {
        // Parse lines like:
        //   Total processed: 123
        //   New:      45
        //   Exists:   67
        //   Skipped:  11
        //   Errors:   0
        auto extract_number = [&output](const std::string& key) -> int {
            size_t pos = output.find(key);
            if (pos == std::string::npos) return 0;
            pos += key.length();
            // Skip whitespace
            while (pos < output.length() && (output[pos] == ' ' || output[pos] == ':')) pos++;
            // Extract number
            std::string num;
            while (pos < output.length() && std::isdigit(output[pos])) {
                num += output[pos++];
            }
            return num.empty() ? 0 : std::stoi(num);
        };

        stats.total = extract_number("Total processed");
        stats.new_count = extract_number("New:");
        stats.exists = extract_number("Exists:");
        stats.skip = extract_number("Skipped:");
        stats.error = extract_number("Errors:");
    }

    void setup_ida_environment() {
        if (g_config.no_plugins) {
            g_block_plugins = true;

            const char* idadir = real_getenv("IDADIR");
            const char* home = real_getenv("HOME");

            if (idadir && home) {
                std::string real_idadir = idadir;
                std::string fake_base = g_config.work_dir + "/.ida_env";
                std::string fake_idadir = fake_base + "/ida";
                std::string fake_plugins = fake_idadir + "/plugins";

                // Clean up old environment first
                std::error_code ec;
                fs::remove_all(fake_base, ec);

                fs::create_directories(fake_plugins);

                // Symlink hexrays decompiler plugins
                std::string real_plugins = real_idadir + "/plugins";
                if (fs::exists(real_plugins)) {
                    for (const auto& entry : fs::directory_iterator(real_plugins)) {
                        if (entry.path().filename().string().substr(0, 3) == "hex") {
                            fs::create_symlink(entry.path(), fake_plugins + "/" + entry.path().filename().string());
                        }
                    }
                }

                // Symlink all entries from real IDADIR except plugins
                for (const auto& entry : fs::directory_iterator(real_idadir)) {
                    if (entry.path().filename() == "plugins") continue;
                    std::string dst = fake_idadir + "/" + entry.path().filename().string();
                    if (!fs::exists(dst)) {
                        fs::create_symlink(entry.path(), dst);
                    }
                }

                real_setenv("IDADIR", fake_idadir.c_str());

                // Also redirect IDAUSR
                std::string real_idausr = std::string(home) + "/.idapro";
                std::string fake_idausr = fake_base + "/user";
                fs::create_directories(fake_idausr);
                if (fs::exists(real_idausr + "/ida.reg")) {
                    fs::create_symlink(real_idausr + "/ida.reg", fake_idausr + "/ida.reg");
                }
                real_setenv("IDAUSR", fake_idausr.c_str());
            }
        }
    }

    JobQueue& m_queue;
    StatusCallback m_status_callback;
    std::vector<std::thread> m_threads;
    std::atomic<bool> m_running{true};
};

//=============================================================================
// Overloaded Helper (from TDLib example)
//=============================================================================

namespace detail {
template <class... Fs>
struct overload;

template <class F>
struct overload<F> : public F {
    explicit overload(F f) : F(f) {}
};

template <class F, class... Fs>
struct overload<F, Fs...> : public overload<F>, public overload<Fs...> {
    overload(F f, Fs... fs) : overload<F>(f), overload<Fs...>(fs...) {}
    using overload<F>::operator();
    using overload<Fs...>::operator();
};
}  // namespace detail

template <class... F>
auto overloaded(F... f) {
    return detail::overload<F...>(f...);
}

//=============================================================================
// Telegram Bot
//=============================================================================

class LuminaBot {
public:
    using Object = td_api::object_ptr<td_api::Object>;

    LuminaBot() : m_worker(m_job_queue, [this](int64_t job_id, JobStatus status, const std::string& detail) {
        on_job_status_changed(job_id, status, detail);
    }) {
        // Create work directory
        fs::create_directories(g_config.work_dir);

        // Initialize TDLib
        td::ClientManager::execute(td_api::make_object<td_api::setLogVerbosityLevel>(1));
        m_client_manager = std::make_unique<td::ClientManager>();
        m_client_id = m_client_manager->create_client_id();
        send_query(td_api::make_object<td_api::getOption>("version"), {});
    }

    void run() {
        m_worker.start();

        while (!m_need_quit) {
            auto response = m_client_manager->receive(1.0);
            if (response.object) {
                process_response(std::move(response));
            }

            // Process any pending status updates
            process_pending_updates();
        }

        m_worker.stop();
    }

private:
    void send_query(td_api::object_ptr<td_api::Function> f, std::function<void(Object)> handler) {
        auto query_id = next_query_id();
        if (handler) {
            m_handlers.emplace(query_id, std::move(handler));
        }
        m_client_manager->send(m_client_id, query_id, std::move(f));
    }

    void process_response(td::ClientManager::Response response) {
        if (!response.object) return;

        if (response.request_id == 0) {
            process_update(std::move(response.object));
        } else {
            auto it = m_handlers.find(response.request_id);
            if (it != m_handlers.end()) {
                it->second(std::move(response.object));
                m_handlers.erase(it);
            }
        }
    }

    void process_update(td_api::object_ptr<td_api::Object> update) {
        // Debug: show update type
        std::cout << "[Bot] Update type: " << update->get_id() << std::endl;

        td_api::downcast_call(*update, overloaded(
            [this](td_api::updateAuthorizationState& update_auth) {
                m_authorization_state = std::move(update_auth.authorization_state_);
                on_authorization_state_update();
            },
            [this](td_api::updateNewMessage& update) {
                on_new_message(std::move(update.message_));
            },
            [this](td_api::updateFile& update) {
                on_file_update(std::move(update.file_));
            },
            [](auto&) {}
        ));
    }

    void on_authorization_state_update() {
        td_api::downcast_call(*m_authorization_state, overloaded(
            [this](td_api::authorizationStateReady&) {
                m_is_authorized = true;
                std::cout << "[Bot] Authorized and ready!" << std::endl;
            },
            [this](td_api::authorizationStateLoggingOut&) {
                m_is_authorized = false;
                std::cout << "[Bot] Logging out..." << std::endl;
            },
            [](td_api::authorizationStateClosing&) {
                std::cout << "[Bot] Closing..." << std::endl;
            },
            [this](td_api::authorizationStateClosed&) {
                m_is_authorized = false;
                m_need_quit = true;
                std::cout << "[Bot] Terminated" << std::endl;
            },
            [this](td_api::authorizationStateWaitTdlibParameters&) {
                auto request = td_api::make_object<td_api::setTdlibParameters>();
                request->database_directory_ = g_config.tdlib_dir;
                request->use_message_database_ = true;
                request->use_secret_chats_ = false;
                request->api_id_ = std::stoi(g_config.api_id);
                request->api_hash_ = g_config.api_hash;
                request->system_language_code_ = "en";
                request->device_model_ = "Server";
                request->application_version_ = "1.0";
                send_query(std::move(request), {});
            },
            [this](td_api::authorizationStateWaitPhoneNumber&) {
                // Use bot token authentication
                send_query(td_api::make_object<td_api::checkAuthenticationBotToken>(g_config.bot_token), {});
            },
            [](auto&) {}
        ));
    }

    void on_new_message(td_api::object_ptr<td_api::message> message) {
        if (!message) return;

        // Skip outgoing messages (from the bot itself)
        if (message->is_outgoing_) return;

        auto chat_id = message->chat_id_;
        auto message_id = message->id_;

        // Check if this is a reply to another message
        int64_t reply_to_message_id = 0;
        if (message->reply_to_ && message->reply_to_->get_id() == td_api::messageReplyToMessage::ID) {
            auto& reply = static_cast<td_api::messageReplyToMessage&>(*message->reply_to_);
            reply_to_message_id = reply.message_id_;
        }

        std::cout << "[Bot] Received message in chat " << chat_id
                  << ", content type: " << message->content_->get_id();
        if (reply_to_message_id) {
            std::cout << ", reply_to: " << reply_to_message_id;
        }
        std::cout << std::endl;

        // Handle document (file) messages
        if (message->content_->get_id() == td_api::messageDocument::ID) {
            auto& doc = static_cast<td_api::messageDocument&>(*message->content_);
            std::cout << "[Bot] Document received: " << doc.document_->file_name_ << std::endl;
            handle_document(chat_id, message_id, reply_to_message_id, std::move(doc.document_));
            return;
        }

        // Handle text commands
        if (message->content_->get_id() == td_api::messageText::ID) {
            auto& text = static_cast<td_api::messageText&>(*message->content_);
            std::cout << "[Bot] Text received: " << text.text_->text_ << std::endl;
            handle_command(chat_id, message_id, text.text_->text_);
        }
    }

    void handle_command(int64_t chat_id, int64_t /*message_id*/, const std::string& text) {
        std::cout << "[Bot] handle_command: '" << text << "'" << std::endl;
        if (text == "/start" || text == "/help") {
            std::cout << "[Bot] Sending help message to " << chat_id << std::endl;
            send_message(chat_id,
                "\xF0\x9F\x94\xAC *Lumina Symbol Submission Bot*\n\n"
                "Send me binary files \\(ELF, PE/DLL, Mach\\-O\\) and I'll extract their symbols "
                "and push them to the Hex\\-Rays Lumina server\\.\n\n"
                "*Supported features:*\n"
                "\xE2\x80\xA2 Automatic DWARF debug info extraction\n"
                "\xE2\x80\xA2 PE/DLL files with separate PDB support\n"
                "\xE2\x80\xA2 Up to 5 files processed in parallel\n\n"
                "*How to use:*\n"
                "1\\. Send a binary file \\(EXE, DLL, ELF, etc\\.\\)\n"
                "2\\. For PE/DLL: reply to the status message with the PDB\n"
                "3\\. Wait for analysis and Lumina push\n\n"
                "*Commands:*\n"
                "/status \\- Show queue status\n"
                "/help \\- Show this message",
                true);
        } else if (text == "/status") {
            size_t queue_size = m_job_queue.queue_size();
            std::ostringstream ss;
            ss << "\xF0\x9F\x93\x8A *Queue Status*\n\n";
            ss << "Jobs in queue: " << queue_size << "\n";
            send_message(chat_id, ss.str(), true);
        } else if (text == "/go") {
            // Start analysis for a PE file without PDB
            handle_go_command(chat_id);
        }
    }

    void handle_go_command(int64_t chat_id) {
        // Find a job in this chat that's waiting for PDB
        std::shared_ptr<AnalysisJob> job = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_job_queue.get_mutex());
            for (auto& [id, j] : m_job_queue.get_jobs()) {
                if (j->chat_id == chat_id && j->waiting_for_pdb) {
                    job = j;
                    break;
                }
            }
        }

        if (!job) {
            send_message(chat_id, "No PE file waiting for analysis\\.", true);
            return;
        }

        job->waiting_for_pdb = false;
        update_status_message(job,
            status_emoji(JobStatus::COMPLETED) + " *File:* `" + escape_markdown(job->file_name) + "`\n" +
            status_emoji(JobStatus::COMPLETED) + " File downloaded\n" +
            status_emoji(JobStatus::QUEUED) + " Queued for analysis \\(no PDB\\)");
        m_job_queue.enqueue(job->job_id);
        std::cout << "[Bot] /go - Job " << job->job_id << " enqueued without PDB" << std::endl;
    }

    void handle_document(int64_t chat_id, int64_t message_id, int64_t reply_to_message_id,
                         td_api::object_ptr<td_api::document> doc) {
        std::cout << "[Bot] handle_document called" << std::endl;
        if (!doc) {
            std::cout << "[Bot] doc is null" << std::endl;
            return;
        }
        if (!doc->document_) {
            std::cout << "[Bot] doc->document_ is null" << std::endl;
            return;
        }

        std::string file_name = doc->file_name_;
        int32_t file_id = doc->document_->id_;
        int64_t file_size = doc->document_->size_;
        std::cout << "[Bot] File: " << file_name << ", id=" << file_id << ", size=" << file_size << std::endl;

        // Check file size
        if (file_size > static_cast<int64_t>(g_config.max_file_size)) {
            send_message(chat_id,
                "\xE2\x9D\x8C File too large\\. Maximum size is " +
                std::to_string(g_config.max_file_size / (1024 * 1024)) + " MB\\.", true);
            return;
        }

        // Check if this is a PDB file being added to an existing job (reply to status message)
        bool is_pdb = file_name.size() > 4 &&
            (file_name.substr(file_name.size() - 4) == ".pdb" ||
             file_name.substr(file_name.size() - 4) == ".PDB");

        if (is_pdb) {
            std::shared_ptr<AnalysisJob> job = nullptr;

            // First try to match by reply_to message ID
            if (reply_to_message_id != 0) {
                job = m_job_queue.find_job_by_message(chat_id, reply_to_message_id);
                if (job) {
                    std::cout << "[Bot] PDB matched by reply_to message ID " << reply_to_message_id << std::endl;
                }
            }

            // If no match by reply, find any job in this chat waiting for PDB
            if (!job) {
                job = m_job_queue.find_job_waiting_for_pdb(chat_id);
                if (job) {
                    std::cout << "[Bot] PDB matched to job waiting for PDB in chat" << std::endl;
                }
            }

            if (job && job->waiting_for_pdb) {
                std::cout << "[Bot] PDB file for job " << job->job_id << std::endl;
                handle_pdb_upload(job, file_id, file_name);
                return;
            }
        }

        // Create a new job for this binary
        int64_t job_id = m_job_queue.add_job(chat_id, message_id, file_name);
        auto job = m_job_queue.get_job(job_id);
        job->file_id = file_id;

        // Map file_id to job_id for download tracking
        {
            std::lock_guard<std::mutex> lock(m_download_mutex);
            m_file_downloads[file_id] = job_id;
        }

        // Send initial status message
        send_message(chat_id,
            status_emoji(JobStatus::DOWNLOADING) + " *Received:* `" + escape_markdown(file_name) + "`\n" +
            status_emoji(JobStatus::DOWNLOADING) + " Downloading file\\.\\.\\.",
            true,
            [this, job_id](Object obj) {
                std::cout << "[Bot] send_message callback, obj type=" << obj->get_id() << std::endl;
                if (obj->get_id() == td_api::message::ID) {
                    auto& msg = static_cast<td_api::message&>(*obj);
                    std::cout << "[Bot] Got message id=" << msg.id_ << std::endl;
                    auto job = m_job_queue.get_job(job_id);
                    if (job) {
                        job->status_message_id = msg.id_;
                        std::cout << "[Bot] Set status_message_id=" << msg.id_ << " for job " << job_id << std::endl;
                    } else {
                        std::cout << "[Bot] Job " << job_id << " not found in callback" << std::endl;
                    }
                } else if (obj->get_id() == td_api::error::ID) {
                    auto& err = static_cast<td_api::error&>(*obj);
                    std::cout << "[Bot] Error sending message: " << err.message_ << std::endl;
                }
            });

        job->status = JobStatus::DOWNLOADING;

        // Start download
        send_query(td_api::make_object<td_api::downloadFile>(file_id, 1, 0, 0, true), {});
    }

    void on_file_update(td_api::object_ptr<td_api::file> file) {
        if (!file) return;

        std::cout << "[Bot] File update: id=" << file->id_
                  << ", downloaded=" << (file->local_ ? file->local_->is_downloading_completed_ : false)
                  << ", path=" << (file->local_ ? file->local_->path_ : "null") << std::endl;

        if (!file->local_ || !file->local_->is_downloading_completed_) return;

        int32_t file_id = file->id_;
        std::string local_path = file->local_->path_;
        std::cout << "[Bot] Download complete: id=" << file_id << ", path=" << local_path << std::endl;

        // Check if this is a PDB download
        {
            std::lock_guard<std::mutex> lock(m_download_mutex);
            auto pdb_it = m_pdb_downloads.find(file_id);
            if (pdb_it != m_pdb_downloads.end()) {
                int64_t job_id = pdb_it->second;
                m_pdb_downloads.erase(pdb_it);
                auto job = m_job_queue.get_job(job_id);
                if (job) {
                    on_pdb_download_complete(job, local_path);
                }
                return;
            }
        }

        // Find the job for this binary file
        int64_t job_id = 0;
        {
            std::lock_guard<std::mutex> lock(m_download_mutex);
            auto it = m_file_downloads.find(file_id);
            if (it != m_file_downloads.end()) {
                job_id = it->second;
                m_file_downloads.erase(it);
                std::cout << "[Bot] Found job_id=" << job_id << " for file_id=" << file_id << std::endl;
            }
        }

        if (job_id == 0) {
            return;
        }

        auto job = m_job_queue.get_job(job_id);
        if (!job) {
            return;
        }

        std::cout << "[Bot] Processing job " << job_id << " for file " << job->file_name << std::endl;

        // Move file to work directory with hashed filename
        std::string ext = get_extension(job->file_name);
        std::string dest_path = g_config.work_dir + "/" + job->file_hash + ext;
        std::cout << "[Bot] Copying " << local_path << " to " << dest_path << std::endl;
        try {
            fs::copy_file(local_path, dest_path, fs::copy_options::overwrite_existing);
            job->local_path = dest_path;
            job->tdlib_doc_path = local_path;  // Track for cleanup
            std::cout << "[Bot] Copy successful" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "[Bot] Copy failed: " << e.what() << std::endl;
            update_status_message(job, "Download failed: " + std::string(e.what()));
            m_job_queue.update_status(job_id, JobStatus::FAILED, e.what());
            return;
        }

        std::cout << "[Bot] Updating status message" << std::endl;

        // Check if this is a PE/DLL file that might have a PDB
        bool is_pe = false;
        std::string lower_name = job->file_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        if (lower_name.size() > 4) {
            std::string ext = lower_name.substr(lower_name.size() - 4);
            is_pe = (ext == ".exe" || ext == ".dll" || ext == ".sys");
        }

        if (is_pe) {
            // For PE files, wait for PDB or /go command
            job->waiting_for_pdb = true;
            update_status_message(job,
                status_emoji(JobStatus::COMPLETED) + " *File:* `" + escape_markdown(job->file_name) + "`\n" +
                status_emoji(JobStatus::COMPLETED) + " File downloaded\n\n" +
                "\xF0\x9F\x93\x8E *PE file detected*\n" +
                "Reply to this message with a PDB file, or\n" +
                "Send /go to analyze without PDB");
            std::cout << "[Bot] PE file - waiting for PDB or /go" << std::endl;
        } else {
            // For non-PE files, enqueue immediately
            update_status_message(job,
                status_emoji(JobStatus::COMPLETED) + " File downloaded\n" +
                status_emoji(JobStatus::QUEUED) + " Queued for analysis");
            m_job_queue.enqueue(job_id);
            std::cout << "[Bot] Job enqueued" << std::endl;
        }
    }

    void handle_pdb_upload(std::shared_ptr<AnalysisJob> job, int32_t file_id, const std::string& pdb_name) {
        std::cout << "[Bot] Handling PDB upload for job " << job->job_id << std::endl;

        // Update status to show we're downloading the PDB
        update_status_message(job,
            status_emoji(JobStatus::COMPLETED) + " *File:* `" + escape_markdown(job->file_name) + "`\n" +
            status_emoji(JobStatus::COMPLETED) + " File downloaded\n" +
            status_emoji(JobStatus::DOWNLOADING) + " Downloading PDB: `" + escape_markdown(pdb_name) + "`");

        // Track this PDB download
        {
            std::lock_guard<std::mutex> lock(m_download_mutex);
            m_pdb_downloads[file_id] = job->job_id;
        }

        // Request download
        send_query(td_api::make_object<td_api::downloadFile>(file_id, 1, 0, 0, true), {});
    }

    void on_pdb_download_complete(std::shared_ptr<AnalysisJob> job, const std::string& local_path) {
        std::cout << "[Bot] PDB download complete for job " << job->job_id << std::endl;

        // Copy PDB to work directory with hashed filename
        // Use same hash as binary so IDA finds it automatically
        std::string pdb_dest = g_config.work_dir + "/" + job->file_hash + ".pdb";

        try {
            fs::copy_file(local_path, pdb_dest, fs::copy_options::overwrite_existing);
            job->pdb_path = pdb_dest;
            job->tdlib_pdb_path = local_path;  // Track for cleanup
            std::cout << "[Bot] PDB copied to " << pdb_dest << std::endl;

            update_status_message(job,
                status_emoji(JobStatus::COMPLETED) + " *File:* `" + escape_markdown(job->file_name) + "`\n" +
                status_emoji(JobStatus::COMPLETED) + " File downloaded\n" +
                status_emoji(JobStatus::COMPLETED) + " PDB attached\n" +
                status_emoji(JobStatus::QUEUED) + " Queued for analysis");
        } catch (const std::exception& e) {
            std::cout << "[Bot] Failed to copy PDB: " << e.what() << std::endl;
            update_status_message(job,
                status_emoji(JobStatus::COMPLETED) + " *File:* `" + escape_markdown(job->file_name) + "`\n" +
                status_emoji(JobStatus::COMPLETED) + " File downloaded\n" +
                "\xE2\x9A\xA0 PDB copy failed, continuing without it\n" +
                status_emoji(JobStatus::QUEUED) + " Queued for analysis");
        }

        // Now enqueue the job for processing
        job->waiting_for_pdb = false;
        m_job_queue.enqueue(job->job_id);
        std::cout << "[Bot] Job " << job->job_id << " enqueued with PDB" << std::endl;
    }

    void on_job_status_changed(int64_t job_id, JobStatus status, const std::string& detail) {
        // Queue the update to be processed in the main thread
        std::lock_guard<std::mutex> lock(m_update_mutex);
        m_pending_status_updates.push_back({job_id, status, detail});
    }

    void process_pending_updates() {
        std::vector<std::tuple<int64_t, JobStatus, std::string>> updates;
        {
            std::lock_guard<std::mutex> lock(m_update_mutex);
            updates = std::move(m_pending_status_updates);
            m_pending_status_updates.clear();
        }

        for (const auto& [job_id, status, detail] : updates) {
            auto job = m_job_queue.get_job(job_id);
            if (!job) continue;

            job->status = status;

            std::ostringstream ss;
            ss << status_emoji(JobStatus::COMPLETED) << " *File:* `" << escape_markdown(job->file_name) << "`\n";

            switch (status) {
                case JobStatus::ANALYZING:
                    ss << status_emoji(status) << " Analyzing binary\\.\\.\\.";
                    break;

                case JobStatus::CONNECTING_LUMINA:
                    ss << status_emoji(JobStatus::COMPLETED) << " Analysis complete\n";
                    ss << "   • Functions: " << job->function_count << "\n";
                    ss << status_emoji(status) << " Connecting to Lumina\\.\\.\\.";
                    break;

                case JobStatus::PUSHING:
                    ss << status_emoji(JobStatus::COMPLETED) << " Connected to Lumina\n";
                    ss << status_emoji(status) << " Pushing symbols\\.\\.\\.";
                    break;

                case JobStatus::COMPLETED: {
                    auto& stats = job->push_stats;

                    ss << status_emoji(status) << " *Completed\\!*\n\n";
                    ss << "\xF0\x9F\x93\x8A *Results:*\n";
                    ss << "   • Total functions: " << stats.total << "\n";
                    ss << "   • New symbols: " << stats.new_count << "\n";
                    ss << "   • Already existed: " << stats.exists << "\n";
                    ss << "   • Skipped: " << stats.skip;
                    if (stats.error > 0) {
                        ss << "\n   • Errors: " << stats.error;
                    }
                    break;
                }

                case JobStatus::FAILED:
                    ss << status_emoji(status) << " *Failed*\n\n";
                    ss << "Error: " << escape_markdown(detail.empty() ? job->error_message : detail);
                    break;

                default:
                    ss << status_emoji(status) << " " << status_to_string(status);
                    break;
            }

            update_status_message(job, ss.str());

            // Clean up completed/failed jobs after some time
            if (status == JobStatus::COMPLETED || status == JobStatus::FAILED) {
                // In production, use a proper timer
                m_job_queue.remove_job(job_id);
            }
        }
    }

    void send_message(int64_t chat_id, const std::string& text, bool markdown = false,
                      std::function<void(Object)> handler = {}) {
        std::cout << "[Bot] send_message to " << chat_id << ", markdown=" << markdown << std::endl;

        if (markdown) {
            auto parse_mode = td_api::make_object<td_api::textParseModeMarkdown>(2);
            send_query(
                td_api::make_object<td_api::parseTextEntities>(text, std::move(parse_mode)),
                [this, chat_id, text, handler](Object obj) mutable {
                    if (obj->get_id() == td_api::formattedText::ID) {
                        auto formatted = td::move_tl_object_as<td_api::formattedText>(obj);
                        auto msg = td_api::make_object<td_api::sendMessage>();
                        msg->chat_id_ = chat_id;
                        auto content = td_api::make_object<td_api::inputMessageText>();
                        content->text_ = std::move(formatted);
                        msg->input_message_content_ = std::move(content);
                        std::cout << "[Bot] Sending formatted message" << std::endl;
                        send_query(std::move(msg), std::move(handler));
                    } else if (obj->get_id() == td_api::error::ID) {
                        auto err = td::move_tl_object_as<td_api::error>(obj);
                        std::cout << "[Bot] Markdown parse error: " << err->message_ << std::endl;
                        // Fall back to plain text
                        auto msg = td_api::make_object<td_api::sendMessage>();
                        msg->chat_id_ = chat_id;
                        auto content = td_api::make_object<td_api::inputMessageText>();
                        content->text_ = td_api::make_object<td_api::formattedText>();
                        content->text_->text_ = text;
                        msg->input_message_content_ = std::move(content);
                        send_query(std::move(msg), std::move(handler));
                    } else {
                        std::cout << "[Bot] Unexpected parse result: " << obj->get_id() << std::endl;
                    }
                });
        } else {
            auto msg = td_api::make_object<td_api::sendMessage>();
            msg->chat_id_ = chat_id;
            auto content = td_api::make_object<td_api::inputMessageText>();
            content->text_ = td_api::make_object<td_api::formattedText>();
            content->text_->text_ = text;
            msg->input_message_content_ = std::move(content);
            send_query(std::move(msg), std::move(handler));
        }
    }

    void update_status_message(std::shared_ptr<AnalysisJob> job, const std::string& text) {
        std::cout << "[Bot] update_status_message: job=" << job->job_id
                  << ", status_message_id=" << job->status_message_id << std::endl;

        // Send a new message and update the status_message_id so replies work
        send_message(job->chat_id, text, true, [job](Object obj) {
            if (obj->get_id() == td_api::message::ID) {
                auto& msg = static_cast<td_api::message&>(*obj);
                job->status_message_id = msg.id_;
                std::cout << "[Bot] Updated status_message_id to " << msg.id_ << " for job " << job->job_id << std::endl;
            }
        });
    }

    std::uint64_t next_query_id() {
        return ++m_current_query_id;
    }

    std::unique_ptr<td::ClientManager> m_client_manager;
    std::int32_t m_client_id{0};
    td_api::object_ptr<td_api::AuthorizationState> m_authorization_state;
    bool m_is_authorized{false};
    bool m_need_quit{false};
    std::uint64_t m_current_query_id{0};
    std::map<std::uint64_t, std::function<void(Object)>> m_handlers;

    JobQueue m_job_queue;
    AnalysisWorker m_worker;

    std::mutex m_download_mutex;
    std::map<int32_t, int64_t> m_file_downloads;  // file_id -> job_id
    std::map<int32_t, int64_t> m_pdb_downloads;   // file_id -> job_id (for PDB files)

    std::mutex m_update_mutex;
    std::vector<std::tuple<int64_t, JobStatus, std::string>> m_pending_status_updates;
};

//=============================================================================
// Main
//=============================================================================

void print_usage(const char* prog) {
    std::cout << "Telegram Lumina Bot\n\n";
    std::cout << "Usage: " << prog << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --api-id <id>       Telegram API ID (or TELEGRAM_API_ID env)\n";
    std::cout << "  --api-hash <hash>   Telegram API hash (or TELEGRAM_API_HASH env)\n";
    std::cout << "  --bot-token <token> Bot token from @BotFather (or TELEGRAM_BOT_TOKEN env)\n";
    std::cout << "  --work-dir <path>   Working directory for temp files (default: /tmp/lumina_bot)\n";
    std::cout << "  --tdlib-dir <path>  TDLib database directory (default: tdlib_bot)\n";
    std::cout << "  --ida-lumina <path> Path to ida_lumina tool (default: ./ida_lumina)\n";
    std::cout << "  --max-size <mb>     Maximum file size in MB (default: 100)\n";
    std::cout << "  --no-plugins        Disable loading user plugins (default)\n";
    std::cout << "  --plugins           Enable loading user plugins\n";
    std::cout << "  -h, --help          Show this help\n";
    std::cout << "\n";
    std::cout << "Environment variables:\n";
    std::cout << "  TELEGRAM_API_ID     - Telegram API ID\n";
    std::cout << "  TELEGRAM_API_HASH   - Telegram API hash\n";
    std::cout << "  TELEGRAM_BOT_TOKEN  - Bot token from @BotFather\n";
    std::cout << "  IDADIR              - Path to IDA Pro installation\n";
    std::cout << "\n";
}

bool parse_args(int argc, char* argv[]) {
    // Load from environment first
    if (const char* val = real_getenv("TELEGRAM_API_ID")) {
        g_config.api_id = val;
    }
    if (const char* val = real_getenv("TELEGRAM_API_HASH")) {
        g_config.api_hash = val;
    }
    if (const char* val = real_getenv("TELEGRAM_BOT_TOKEN")) {
        g_config.bot_token = val;
    }

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        } else if (arg == "--api-id" && i + 1 < argc) {
            g_config.api_id = argv[++i];
        } else if (arg == "--api-hash" && i + 1 < argc) {
            g_config.api_hash = argv[++i];
        } else if (arg == "--bot-token" && i + 1 < argc) {
            g_config.bot_token = argv[++i];
        } else if (arg == "--work-dir" && i + 1 < argc) {
            g_config.work_dir = argv[++i];
        } else if (arg == "--tdlib-dir" && i + 1 < argc) {
            g_config.tdlib_dir = argv[++i];
        } else if (arg == "--max-size" && i + 1 < argc) {
            g_config.max_file_size = std::stoull(argv[++i]) * 1024 * 1024;
        } else if (arg == "--ida-lumina" && i + 1 < argc) {
            g_config.ida_lumina_path = argv[++i];
        } else if (arg == "--no-plugins") {
            g_config.no_plugins = true;
        } else if (arg == "--plugins") {
            g_config.no_plugins = false;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
    }

    // Validate required options
    if (g_config.api_id.empty()) {
        std::cerr << "Error: --api-id or TELEGRAM_API_ID required\n";
        return false;
    }
    if (g_config.api_hash.empty()) {
        std::cerr << "Error: --api-hash or TELEGRAM_API_HASH required\n";
        return false;
    }
    if (g_config.bot_token.empty()) {
        std::cerr << "Error: --bot-token or TELEGRAM_BOT_TOKEN required\n";
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    if (!parse_args(argc, argv)) {
        std::cerr << "Use --help for usage information\n";
        return EXIT_FAILURE;
    }

    std::cout << "Starting Lumina Bot...\n";
    std::cout << "Work directory: " << g_config.work_dir << "\n";
    std::cout << "ida_lumina path: " << g_config.ida_lumina_path << "\n";
    std::cout << "Max file size: " << (g_config.max_file_size / (1024 * 1024)) << " MB\n";
    std::cout << "No plugins: " << (g_config.no_plugins ? "yes" : "no") << "\n";

    try {
        LuminaBot bot;
        bot.run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
