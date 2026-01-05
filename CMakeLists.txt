cmake_minimum_required(VERSION 3.10)
project(idalib-dump)

# IDA SDK location (override with -DIDASDK=/path/to/idasdk)
set(IDASDK_VER "92" CACHE STRING "92")
set(IDASDK $ENV{IDASDK} CACHE PATH "Path to IDA SDK")

message(STATUS "Building ${PROJECT_NAME}")
message(STATUS "Using IDA SDK dir: ${IDASDK}")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

# On macOS, we need to set rpath to find libidalib.dylib and libida.dylib
# These are linked with @rpath references, so we MUST have an LC_RPATH entry
if(APPLE)
    # Don't skip rpath on macOS - we need it for @rpath references to work
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    # Default to IDA's MacOS directory
    set(IDA_MACOS_DIR "/Applications/IDA Professional 9.3.app/Contents/MacOS" CACHE PATH "Path to IDA MacOS directory")
    set(CMAKE_BUILD_RPATH "${IDA_MACOS_DIR}")
    set(CMAKE_INSTALL_RPATH "${IDA_MACOS_DIR}")
else()
    set(CMAKE_SKIP_RPATH TRUE)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

ida_add_idalib(ida_dump
  TYPE EXECUTABLE
  SOURCES
    src/main.cpp
    src/noplugins.c
    vendor/kat/highlight.c
    vendor/kat/hashtable.c
    vendor/astyle/src/ASBeautifier.cpp
    vendor/astyle/src/ASFormatter.cpp
    vendor/astyle/src/ASEnhancer.cpp
    vendor/astyle/src/ASLocalizer.cpp
    vendor/astyle/src/ASResource.cpp
    vendor/astyle/src/astyle_main.cpp
  INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/vendor/kat/include
    ${CMAKE_CURRENT_LIST_DIR}/vendor/astyle/src
)

target_compile_definitions(ida_dump PRIVATE ASTYLE_LIB ASTYLE_NO_EXPORT)
target_compile_features(ida_dump PRIVATE cxx_std_17)

# Use flat namespace to work around SDK stub library symbol mismatch
# (SDK exports qfree etc from libidalib stub but runtime has them in libida)
if(APPLE)
    target_link_options(ida_dump PRIVATE -Wl,-flat_namespace)
endif()

# Generate debug info
if(MSVC)
    add_compile_options(/Zi)
    add_link_options(/DEBUG /OPT:REF /OPT:ICF)
else()
    # For GCC/Clang on Linux/Unix
    add_compile_options(-g)
endif()

# Lumina push tool
ida_add_idalib(ida_lumina
  TYPE EXECUTABLE
  SOURCES
    src/lumina.cpp
    src/noplugins.c
  INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/vendor/kat/include
)

target_compile_features(ida_lumina PRIVATE cxx_std_17)
if(NOT WIN32)
    target_link_libraries(ida_lumina PRIVATE dl)
endif()

# Telegram Lumina Bot (optional, requires TDLib, Linux only)
option(BUILD_LUMINA_BOT "Build the Telegram Lumina bot (requires TDLib)" OFF)

if(BUILD_LUMINA_BOT AND NOT WIN32)
    find_package(Td QUIET)
    if(Td_FOUND)
        message(STATUS "TDLib found, building lumina_bot")

        ida_add_idalib(lumina_bot
          TYPE EXECUTABLE
          SOURCES
            src/lumina_bot.cpp
            src/noplugins.c
          INCLUDES
            ${CMAKE_CURRENT_LIST_DIR}/vendor/kat/include
        )

        target_compile_features(lumina_bot PRIVATE cxx_std_17)
        target_link_libraries(lumina_bot PRIVATE Td::TdStatic dl pthread)
    else()
        message(WARNING "TDLib not found. Install TDLib to build lumina_bot.")
        message(STATUS "  TDLib: https://github.com/tdlib/td")
        message(STATUS "  Build with: cmake -DBUILD_LUMINA_BOT=ON -DTd_DIR=/path/to/td/lib/cmake/Td")
    endif()
elseif(BUILD_LUMINA_BOT AND WIN32)
    message(STATUS "Skipping lumina_bot on Windows (TDLib not supported)")
endif()

