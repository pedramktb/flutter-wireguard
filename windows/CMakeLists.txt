cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "flutter_wireguard")
project(${PROJECT_NAME} LANGUAGES CXX)

cmake_policy(VERSION 3.14...3.25)

set(PLUGIN_NAME "flutter_wireguard_plugin")
set(HELPER_NAME "flutter_wireguard_helper")

# ---------------------------------------------------------------------------
# Plugin DLL (loaded into the unprivileged Flutter UI process).
# ---------------------------------------------------------------------------
list(APPEND PLUGIN_SOURCES
  "flutter_wireguard_plugin.cpp"
  "flutter_wireguard_plugin.h"
  "broker_client.cpp"
  "broker_client.h"
  "messages.g.cpp"
  "messages.g.h"
  "utils.cpp"
  "utils.h"
)

add_library(${PLUGIN_NAME} SHARED
  "include/flutter_wireguard/flutter_wireguard_plugin_c_api.h"
  "flutter_wireguard_plugin_c_api.cpp"
  ${PLUGIN_SOURCES}
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL WIN32_LEAN_AND_MEAN)
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(${PLUGIN_NAME} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/wireguard/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin
                                             Wtsapi32 Shell32 Advapi32)

# ---------------------------------------------------------------------------
# Helper exe (broker mode + tunnel-service mode).
# Must NOT depend on Flutter, so it can run as a Windows service under
# LocalSystem.
# ---------------------------------------------------------------------------
add_executable(${HELPER_NAME}
  "helper/main.cpp"
  "helper/broker.cpp"
  "helper/broker.h"
  "helper/pipe_security.cpp"
  "helper/pipe_security.h"
  "helper/tunnel_manager.cpp"
  "helper/tunnel_manager.h"
  "helper/tunnel_service.cpp"
  "helper/tunnel_service.h"
  "helper/config_writer.cpp"
  "helper/config_writer.h"
  "helper/wireguard_dll.cpp"
  "helper/wireguard_dll.h"
  "utils.cpp"
  "utils.h"
)

set_target_properties(${HELPER_NAME} PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  WIN32_EXECUTABLE FALSE)  # console subsystem keeps stderr usable for tests
target_compile_definitions(${HELPER_NAME} PRIVATE WIN32_LEAN_AND_MEAN _UNICODE UNICODE)
target_include_directories(${HELPER_NAME} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/wireguard/include")
target_link_libraries(${HELPER_NAME} PRIVATE Advapi32 Wtsapi32 Crypt32 Shell32 Ole32)

# Both DLLs are loaded at runtime via LoadLibrary inside helper.exe:
#   - wireguard.dll (wireguard-nt) -> driver-control + stats
#   - tunnel.dll    (embeddable)   -> high-level tunnel runtime (wg-quick
#                                     semantics, DNS, routes, kill-switch).
# tunnel.dll is GPLv2 so we deliberately avoid static linking; wireguard.dll
# is MIT but loaded the same way for symmetry and graceful failure.

# ---------------------------------------------------------------------------
# Bundle: plugin DLL + helper exe + the two Go DLLs.
# Pick the right arch slice based on the active MSVC target.
# ---------------------------------------------------------------------------
if (CMAKE_SIZEOF_VOID_P EQUAL 8 AND
    (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR
     CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|aarch64)$"))
  set(_FW_ARCH_DIR "arm64")
else()
  set(_FW_ARCH_DIR "amd64")
endif()

set(_FW_WIREGUARD_DLL
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/wireguard/${_FW_ARCH_DIR}/wireguard.dll")
set(_FW_TUNNEL_DLL
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/tunnel/${_FW_ARCH_DIR}/tunnel.dll")

foreach(_dll IN ITEMS "${_FW_WIREGUARD_DLL}" "${_FW_TUNNEL_DLL}")
  if (NOT EXISTS "${_dll}")
    message(FATAL_ERROR
      "flutter_wireguard: missing prebuilt DLL for arch '${_FW_ARCH_DIR}': "
      "${_dll}\n"
      "See windows/lib/VERSIONS.md for rebuild instructions.")
  endif()
endforeach()

set(flutter_wireguard_bundled_libraries
  "$<TARGET_FILE:${HELPER_NAME}>"
  "${_FW_WIREGUARD_DLL}"
  "${_FW_TUNNEL_DLL}"
  PARENT_SCOPE
)

# ---------------------------------------------------------------------------
# Unit tests (gtest). Built only when the example app sets
# include_${PROJECT_NAME}_tests=ON.
# ---------------------------------------------------------------------------
if (${include_${PROJECT_NAME}_tests})
  enable_testing()
  include(FetchContent)
  if (POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
  endif()
  set(CMAKE_POLICY_VERSION_MINIMUM 3.10 CACHE STRING "" FORCE)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/release-1.12.1.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  set(TEST_RUNNER "${PROJECT_NAME}_test")
  add_executable(${TEST_RUNNER}
    test/name_validation_test.cpp
    test/ipc_protocol_test.cpp
  )
  set_target_properties(${TEST_RUNNER} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)
  target_compile_definitions(${TEST_RUNNER} PRIVATE WIN32_LEAN_AND_MEAN)
  target_include_directories(${TEST_RUNNER} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../cpp")
  target_link_libraries(${TEST_RUNNER} PRIVATE gtest_main gmock)

  include(GoogleTest)
  gtest_discover_tests(${TEST_RUNNER})
endif()
