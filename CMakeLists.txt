
cmake_minimum_required(VERSION 3.10)
project(sscp-host C)

option(SSCP_WITH_OPENSSL "Enable OpenSSL support if available" ON)
option(SSCP_GENERATE_MSVC_MAKEFILE "Generate a make wrapper when using a Visual Studio generator" ON)

set(CMAKE_C_STANDARD 99)
set(LIBRARY_NAME sscp-host)

# Source and header files
include_directories(${PROJECT_SOURCE_DIR}/inc)
file(GLOB SOURCES "src/*.c")

# Try to find OpenSSL
find_package(OpenSSL)
if(OPENSSL_FOUND)
    add_definitions(-DSSCP_WITH_OPENSSL=1)
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(OPENSSL_LIB ${OPENSSL_LIBRARIES})
else()
    add_definitions(-DSSCP_WITH_OPENSSL=0)
    set(OPENSSL_LIB "")
endif()

# Build static library
add_library(${LIBRARY_NAME} STATIC ${SOURCES})

# Example: sscp-test
add_executable(sscp-test examples/sscp-test/main.c)
target_link_libraries(sscp-test ${LIBRARY_NAME} ${OPENSSL_LIB})

# Example: sscp-tool
add_executable(sscp-tool
    examples/sscp-tool/main.c
    examples/sscp-tool/params.c
    examples/sscp-tool/project.h
)
target_link_libraries(sscp-tool ${LIBRARY_NAME} ${OPENSSL_LIB})

# Visual Studio generators are multi-config and do not emit a Makefile.
# This optional wrapper lets users run `make` from the MSVC build directory.
if(SSCP_GENERATE_MSVC_MAKEFILE AND CMAKE_GENERATOR MATCHES "Visual Studio")
    configure_file(
        "${PROJECT_SOURCE_DIR}/cmake/Makefile.msvc.in"
        "${PROJECT_BINARY_DIR}/Makefile"
        @ONLY
    )
endif()
