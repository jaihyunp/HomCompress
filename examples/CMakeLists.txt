# Copyright (C) 2020 IBM Corp.
# This program is Licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. See accompanying LICENSE file.

cmake_minimum_required(VERSION 3.10.2 FATAL_ERROR)

## Use -std=c++17 as default.
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(utils LANGUAGES CXX)

# Define standard installation directories (GNU)
include(GNUInstallDirs)

# Set default output folder
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}")

# STRINGS avoids having the 2 newline characters at the end of the string.
# Alternatively it's possible to use file(READ ...) and then
# string(REGEX REPLACE "\n$" "" HELIB_VERSION "${HELIB_VERSION}")
file(STRINGS "../VERSION" HELIB_VERSION)

find_package(helib "${HELIB_VERSION}" EXACT REQUIRED)

# add_subdirectory(pdq)
add_subdirectory(BGV_binary_arithmetic)
add_subdirectory(BGV_country_db_lookup)
add_subdirectory(BGV_packed_arithmetic)
add_subdirectory(tutorial)
