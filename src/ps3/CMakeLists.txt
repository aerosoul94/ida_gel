cmake_minimum_required(VERSION 2.8)
project(ps3ldr)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/../../cmake)
set(ELF_COMMON_PATH ${CMAKE_SOURCE_DIR}/../elf_common)
set(THIRD_PARTY_PATH ${CMAKE_SOURCE_DIR}/../../third_party)

set(SOURCES
    ${ELF_COMMON_PATH}/elf_reader.hpp
    ${ELF_COMMON_PATH}/elf.h
    ${THIRD_PARTY_PATH}/tinyxml/tinystr.cpp
    ${THIRD_PARTY_PATH}/tinyxml/tinystr.h
    ${THIRD_PARTY_PATH}/tinyxml/tinyxml.cpp
    ${THIRD_PARTY_PATH}/tinyxml/tinyxml.h
    ${THIRD_PARTY_PATH}/tinyxml/tinyxmlerror.cpp
    ${THIRD_PARTY_PATH}/tinyxml/tinyxmlparser.cpp
    cell_loader.cpp
    cell_loader.hpp
    ps3.cpp
    sce.h
)

find_package(IDA)

include_directories(${IDA_INCLUDE_DIR})
include_directories(${IDA_SDK_PATH}/ldr)
include_directories(${ELF_COMMON_PATH})
include_directories(${THIRD_PARTY_PATH}/tinyxml)

add_definitions(${IDA_DEFINITIONS})
add_definitions(-DUSE_STANDARD_FILE_FUNCTIONS) # for tinyxml...

add_library(ps3ldr SHARED ${SOURCES})
target_link_libraries(ps3ldr ${IDA_LIBRARIES})
set_target_properties(ps3ldr PROPERTIES OUTPUT_NAME "ps3" PREFIX "" SUFFIX "${IDA_PLUGIN_EXT}")