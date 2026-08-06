cmake_minimum_required(VERSION 3.25)
project(FileEncryptionTool VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find System Dependencies
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(fmt REQUIRED)
find_package(spdlog REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Build Core Static Engine
add_library(CryptoEngineStatic STATIC
    CryptoCore.cpp
    FileProcessor.cpp
)

target_link_libraries(CryptoEngineStatic
    PUBLIC
        OpenSSL::Crypto
        spdlog::spdlog
        fmt::fmt
        nlohmann_json::nlohmann_json
)

# Build CLI Executable
add_executable(FileEncryptionTool main.cpp)
target_link_libraries(FileEncryptionTool PRIVATE CryptoEngineStatic)

# Enable Security Compiler Flags
if(MSVC)
    target_compile_options(FileEncryptionTool PRIVATE /W4 /WX /GS /sdl)
else()
    target_compile_options(FileEncryptionTool PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2)
endif()