CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(urpc-udp C)

IF(WIN32)
    ADD_LIBRARY(urpc-udp STATIC devudp.c platform-win32.c ring.c)
ELSE()
    ADD_LIBRARY(urpc-udp STATIC devudp.c platform-posix.c ring.c)
ENDIF()

if(MSVC)
     target_compile_options(urpc-udp PRIVATE /W3 /WX)
else()
     target_compile_options(urpc-udp PRIVATE -Wall -Wextra -Werror)
endif()
