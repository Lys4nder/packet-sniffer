cmake_minimum_required(VERSION 3.12)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS ON)

find_package(PcapPlusPlus REQUIRED)

add_executable("${PROJECT_NAME}" main.cpp)

set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
