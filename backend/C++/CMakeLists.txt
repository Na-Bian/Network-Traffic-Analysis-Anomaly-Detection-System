cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT Embedded)
endif()

project(NetworkAnalyzerCore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(network_analyzer_core STATIC
    Graph.cpp
    pathSearch.cpp
)

target_include_directories(network_analyzer_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(network_analyzer_core PUBLIC NOMINMAX)

if(MSVC)
    target_compile_options(network_analyzer_core PUBLIC /utf-8 /permissive-)
else()
    target_compile_options(network_analyzer_core PUBLIC -Wall -Wextra -Wpedantic)
endif()

add_executable(NetworkAnalyzerCore
    main.cpp
)

target_link_libraries(NetworkAnalyzerCore PRIVATE network_analyzer_core)

add_custom_command(TARGET NetworkAnalyzerCore POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:NetworkAnalyzerCore>
        "${CMAKE_CURRENT_SOURCE_DIR}/../NetworkAnalyzerCore.exe"
    COMMENT "Copying NetworkAnalyzerCore.exe to backend runtime directory"
)

add_executable(NetworkAnalyzerBenchmark
    benchmark.cpp
)

target_link_libraries(NetworkAnalyzerBenchmark PRIVATE network_analyzer_core)

set_target_properties(NetworkAnalyzerCore NetworkAnalyzerBenchmark PROPERTIES
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
