cmake_minimum_required(VERSION 3.20)

project("recursiveDNS" LANGUAGES CXX)

add_executable("recursiveDNS" "recursiveDNS.cpp" "winsock.cpp")
target_precompile_headers("recursiveDNS" PRIVATE "pch.hpp")
