cmake_minimum_required(VERSION 3.15)
project(mypkg CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(client)
add_subdirectory(server)
