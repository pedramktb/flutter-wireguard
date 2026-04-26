cmake_minimum_required(VERSION 3.13)

set(PROJECT_NAME "flutter_wireguard")
project(${PROJECT_NAME} LANGUAGES CXX)

set(PLUGIN_NAME "flutter_wireguard_plugin")

list(APPEND PLUGIN_SOURCES
  "flutter_wireguard_plugin.cc"
  "messages.g.cc"
  "privileged_session.cc"
  "process_runner.cc"
  "wg_backend.cc"
)

add_library(${PLUGIN_NAME} SHARED
  ${PLUGIN_SOURCES}
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(${PLUGIN_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::GTK)

set(flutter_wireguard_bundled_libraries
  ""
  PARENT_SCOPE
)

# Unit tests (gtest). Built only when the example app sets
# include_${PROJECT_NAME}_tests=ON.
if (${include_${PROJECT_NAME}_tests})
  set(TEST_RUNNER "${PROJECT_NAME}_test")
  enable_testing()

  include(FetchContent)
  # googletest 1.12.1 still declares cmake_minimum_required(2.8.12) which CMake
  # 3.30+ warns about; pin a modern policy floor for the fetched subtree.
  if (POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)  # use extraction time for FetchContent URLs
  endif()
  set(CMAKE_POLICY_VERSION_MINIMUM 3.10 CACHE STRING "" FORCE)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/release-1.12.1.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of googletest" FORCE)
  FetchContent_MakeAvailable(googletest)

  add_executable(${TEST_RUNNER}
    test/wg_backend_test.cc
    test/process_runner_test.cc
    privileged_session.cc
    process_runner.cc
    wg_backend.cc
  )
  apply_standard_settings(${TEST_RUNNER})
  set_target_properties(${TEST_RUNNER} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)
  target_include_directories(${TEST_RUNNER} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(${TEST_RUNNER} PRIVATE gtest_main gmock)

  include(GoogleTest)
  gtest_discover_tests(${TEST_RUNNER})
endif()
