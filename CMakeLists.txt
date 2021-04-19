# stationaryorbit.encryption:/CMakeLists.txt
# Copyright 2021 zawa-ch.
# GPLv3 (or later) license
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.
# If not, see <http://www.gnu.org/licenses/>.
#
cmake_minimum_required(VERSION 3.16)
project(stationaryorbit.encryption
    VERSION 0.1.0
    LANGUAGES CXX
)
cmake_policy(VERSION 3.13)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

# stationaryorbit.core の探索
if(TARGET stationaryorbit.core)
    message("found stationaryorbit.core in parent project")
    set(stationaryorbit_core_MODULE_NAME stationaryorbit.core)
elseif(EXISTS "dependencies/stationaryorbit.core/CMakeLists.txt")
    message("found stationaryorbit.core in dependencies directory")
    add_subdirectory("dependencies/stationaryorbit.core")
    set(stationaryorbit_core_MODULE_NAME stationaryorbit.core)
else()
    find_path(stationaryorbit_core cmake/Findstationaryorbit.core.cmake
        PATHS
            ..
        PATH_SUFFIXES
            stationaryorbit.core
    )
    if(EXISTS "${stationaryorbit_core}/cmake/Findstationaryorbit.core.cmake")
        message("found Findstationaryorbit.core.cmake in ${stationaryorbit_core}/cmake")
        set(stationaryorbit.core_ROOT "${stationaryorbit_core}")
        set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${stationaryorbit_core}/cmake")
    endif()
    find_package(stationaryorbit.core REQUIRED)
    set(stationaryorbit_core_MODULE_NAME stationaryorbit.core::stationaryorbit.core)
endif()

set(Include_Dir ${PROJECT_SOURCE_DIR}/include)

# stationaryorbit.encryption のビルドとインストール
add_subdirectory(src)
list(APPEND HEADER_DIRECTORIES
    include/stationaryorbit/encryption
)
list(APPEND HEADER_FILES
include/stationaryorbit/encryption.cipher.hpp
)
target_include_directories(stationaryorbit.encryption
    PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    PRIVATE "${PROJECT_BINARY_DIR}/src"
)
target_link_libraries(stationaryorbit.encryption
    ${stationaryorbit_core_MODULE_NAME}
)
set_target_properties(stationaryorbit.encryption PROPERTIES INTERFACE_INCLUDE_DIRECTORIES $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)
install(TARGETS stationaryorbit.encryption
    EXPORT stationaryorbit.encryption.export
    LIBRARY DESTINATION lib
    INCLUDES DESTINATION include
)
install(FILES ${HEADER_FILES} DESTINATION include/stationaryorbit)
install(DIRECTORY ${HEADER_DIRECTORIES} DESTINATION include/stationaryorbit)
install(EXPORT stationaryorbit.encryption.export FILE stationaryorbit.encryption-config.cmake DESTINATION share/cmake/stationaryorbit.encryption/ EXPORT_LINK_INTERFACE_LIBRARIES)

add_subdirectory(test)
