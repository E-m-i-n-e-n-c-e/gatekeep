cmake_minimum_required(VERSION 3.16)
project(gatekeep CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra -Wpedantic)

find_package(Threads REQUIRED)
find_package(nlohmann_json 3 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQ REQUIRED IMPORTED_TARGET libnetfilter_queue)

# Pure logic: parsing, rules, decisions. No kernel or network dependencies,
# so the unit tests link against just this.
add_library(gatekeep_core STATIC
  src/packet.cpp
  src/inspect.cpp
  src/rules.cpp
  src/engine.cpp
)
target_include_directories(gatekeep_core PUBLIC src)
target_link_libraries(gatekeep_core PUBLIC nlohmann_json::nlohmann_json)

add_executable(gatekeep
  src/main.cpp
  src/nfq.cpp
  src/api.cpp
  src/kernel.cpp
)
target_link_libraries(gatekeep PRIVATE gatekeep_core PkgConfig::NFQ Threads::Threads)

add_executable(gatekeep_tests tests/test_main.cpp)
target_link_libraries(gatekeep_tests PRIVATE gatekeep_core)
