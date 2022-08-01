CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(urpc-serial C)

IF(WIN32)
    ADD_LIBRARY(urpc-serial STATIC devserial.c platform-win32.c)
ELSE()
    ADD_LIBRARY(urpc-serial STATIC devserial.c platform-posix.c)
ENDIF()

if(MSVC)
     target_compile_options(urpc-serial PRIVATE /W3 /WX)
else()
     target_compile_options(urpc-serial PRIVATE -Wall -Wextra -Werror)
endif()
