cmake_minimum_required(VERSION 3.15)
project(SecureBox VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${SODIUM_INCLUDE_DIRS})

# Source files
set(SOURCES
    src/crypto.cpp
    src/vault.cpp
    src/metadata.cpp
    src/file_operations.cpp
    src/main.cpp
)

# Create executable
add_executable(securebox ${SOURCES})

# Link libraries
target_link_libraries(securebox ${SODIUM_LIBRARIES})
target_link_directories(securebox PRIVATE ${SODIUM_LIBRARY_DIRS})

# Test executable
set(TEST_SOURCES
    src/crypto.cpp
    src/metadata.cpp
    src/file_operations.cpp
    tests/test_crypto.cpp
)

add_executable(test_crypto ${TEST_SOURCES})
target_link_libraries(test_crypto ${SODIUM_LIBRARIES})
target_link_directories(test_crypto PRIVATE ${SODIUM_LIBRARY_DIRS})

# Installation
install(TARGETS securebox DESTINATION bin)
