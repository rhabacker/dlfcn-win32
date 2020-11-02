cmake_minimum_required(VERSION 2.8.11)

if (NOT DEFINED CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
endif ()

project (dlfcn-win32 C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
include(Macros)

option(BUILD_SHARED_LIBS "shared/static libs" ON) 
option(BUILD_TESTS "tests?" OFF)
if(CMAKE_CROSSCOMPILING)
    add_auto_option(ENABLE_WINE "Enable running tests with wine" AUTO)
    find_program(WINE_EXECUTABLE wine)
    check_auto_option(ENABLE_WINE "wine support" WINE_EXECUTABLE "wine executable")
    if(ENABLE_WINE AND WINE_EXECUTABLE)
        set(WRAPPER ${WINE_EXECUTABLE})
    endif()
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src)

if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
