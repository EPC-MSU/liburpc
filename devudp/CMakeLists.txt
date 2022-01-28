CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(urpc-udp C)

IF(WIN32)
    ADD_LIBRARY(urpc-udp STATIC devudp.c platform-win32.c ring.c)
ELSE()
    ADD_LIBRARY(urpc-udp STATIC devudp.c platform-posix.c ring.c)
ENDIF()
