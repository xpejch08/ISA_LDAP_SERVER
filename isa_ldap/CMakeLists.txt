cmake_minimum_required(VERSION 3.26)
project(ISA_LDAP)

set(CMAKE_CXX_STANDARD 23)

add_executable(ISA_LDAP
        ldap.cpp
        decodeLdap.cpp
        decodeLdap.h
        ldapParser.cpp)
