cmake_minimum_required(VERSION 2.8)
project(wiiuldr)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/../../cmake)
set(ELF_COMMON_PATH ${CMAKE_SOURCE_DIR}/../elf_common)
set(THIRD_PARTY_PATH ${CMAKE_SOURCE_DIR}../../third_party)

set(SOURCES
    ${ELF_COMMON_PATH}/elf_reader.hpp
    ${ELF_COMMON_PATH}/elf.h
    tinfl.c
    cafe_loader.cpp
    cafe_loader.hpp
    wiiu.cpp
    cafe.h
)

find_package(IDA)

include_directories(${IDA_INCLUDE_DIR})
include_directories(${IDA_SDK_PATH}/ldr)
include_directories(${ELF_COMMON_PATH})

add_definitions(${IDA_DEFINITIONS})

add_library(wiiuldr SHARED ${SOURCES})
target_link_libraries(wiiuldr ${IDA_LIBRARIES})
set_target_properties(wiiuldr PROPERTIES OUTPUT_NAME "wiiu" PREFIX "" SUFFIX "${IDA_PLUGIN_EXT}")