cmake_minimum_required(VERSION 2.8)

project(external-boringssl)
include(ExternalProject)

set(ARG_GIT_REPOSITORY https://boringssl.googlesource.com/boringssl)
set(ARG_GIT_TAG 251b5169fd44345f455438312ec4e18ae07fd58c)

list(APPEND CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_INSTALL_PREFIX}"
    "-DBUILD_SHARED_LIBS=OFF"
    )

message(STATUS "Preparing external project \"boringssl\" with args:")
foreach(CMAKE_ARG ${CMAKE_ARGS})
    message(STATUS "-- ${CMAKE_ARG}")
endforeach()

ExternalProject_add(
    boringssl
    GIT_REPOSITORY ${ARG_GIT_REPOSITORY}
    GIT_TAG ${ARG_GIT_TAG}
    PREFIX boringssl
    PATCH_COMMAND git apply ${PROJECT_SOURCE_DIR}/boringssl_install.patch
    CMAKE_ARGS "${CMAKE_ARGS}"
    )
