CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

PROJECT(urpc-serial C)

IF(WIN32)
    ADD_LIBRARY(urpc-serial STATIC devserial.c platform-win32.c)
ELSE()
    ADD_LIBRARY(urpc-serial STATIC devserial.c platform-posix.c)
ENDIF()
