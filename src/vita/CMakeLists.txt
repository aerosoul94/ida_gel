cmake_minimum_required(VERSION 2.8)
project(vitaldr)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/../../cmake)
set(ELF_COMMON_PATH ${CMAKE_SOURCE_DIR}/../elf_common)
set(THIRD_PARTY_PATH ${CMAKE_SOURCE_DIR}/../../third_party)

set(SOURCES
    ${ELF_COMMON_PATH}/elf_reader.h
    ${ELF_COMMON_PATH}/elf.h
    psp2_loader.cpp
    psp2_loader.h
    vita.cpp
    sce.h
)

find_package(IDA)

include_directories(${IDA_INCLUDE_DIR})
include_directories(${IDA_SDK_PATH}/ldr)
include_directories(${ELF_COMMON_PATH})

add_definitions(${IDA_DEFINITIONS})
add_definitions(-DUSE_STANDARD_FILE_FUNCTIONS) 

add_library(vitaldr SHARED ${SOURCES})
target_link_libraries(vitaldr ${IDA_LIBRARIES})
set_target_properties(vitaldr PROPERTIES OUTPUT_NAME "vita" PREFIX "" SUFFIX "${IDA_PLUGIN_EXT}")