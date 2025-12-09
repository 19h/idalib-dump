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
set(CMAKE_SKIP_RPATH TRUE)

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
target_link_libraries(ida_lumina PRIVATE dl)

