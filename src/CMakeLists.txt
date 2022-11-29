# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.13)

project(afetch C CXX)

set(CMAKE_CXX_STANDARD 20)

set(openenclave_curl_BUILD_DIR "" CACHE PATH "Path to openenclave-curl build folder")

find_package(openenclave REQUIRED CONFIG)

add_subdirectory(enclave)
add_subdirectory(host)
