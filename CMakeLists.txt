cmake_minimum_required (VERSION 2.6)
project (final)

find_package(Boost COMPONENTS system filesystem REQUIRED)
find_package(Threads)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_executable(final main.cpp)
target_link_libraries(final
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
)
