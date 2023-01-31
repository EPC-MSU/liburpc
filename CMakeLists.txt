CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(urpc)

OPTION(URPC_ENABLE_SERIAL "Enable serial port devices support" ON)
OPTION(URPC_ENABLE_XINET "Enable network devices support via bindy/cryptopp" ON)
OPTION(URPC_ENABLE_UDP "Enable UDP adapter devices support" ON)

IF(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
    # It is required to build a rpath framework
    CMAKE_POLICY(SET CMP0042 NEW)
ENDIF()

if(${CMAKE_VERSION} VERSION_LESS "3.0.2")
    function(target_include_directories _target)
        set_property(GLOBAL APPEND PROPERTY GLOBAL_TARGETS "${_target}")
        set(_mode "PRIVATE")
        foreach(_arg ${ARGN})
            if (_arg MATCHES "SYSTEM|BEFORE")
                message(FATAL_ERROR "target_include_directories: SYSTEM or BEFORE not supported")
            endif()
            if (_arg MATCHES "INTERFACE|PUBLIC|PRIVATE")
                set(_mode "${_arg}")
            else()
                get_filename_component(_inc_dir "${_arg}" ABSOLUTE)
                if (_mode MATCHES "PUBLIC|PRIVATE")
                    set_property(TARGET ${_target} APPEND PROPERTY INCLUDE_DIRECTORIES "${_inc_dir}")
                endif()
                if (_mode MATCHES "INTERFACE|PUBLIC")
                    set_property(TARGET ${_target} APPEND PROPERTY MY_INTERFACE_INCLUDE_DIRECTORIES "${_inc_dir}")
                endif()
            endif()
        endforeach()
    endfunction(target_include_directories)
endif()

ADD_LIBRARY(urpc urpc.c uri.c synchronizer.c)
CONFIGURE_FILE(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/generated/private/config.h)
target_include_directories(urpc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated/private)
IF(${CMAKE_SYSTEM_NAME} STREQUAL Windows)
   ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
ENDIF()   
INCLUDE(GenerateExportHeader)
GENERATE_EXPORT_HEADER(urpc EXPORT_MACRO_NAME URPC_API_EXPORT EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/generated/public/urpc_export.h)
# make available to all dependants
target_include_directories(urpc PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/generated/public)
# make available to all dev* submodules
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/generated/public)

IF(BUILD_SHARED_LIBS)
    SET_TARGET_PROPERTIES(urpc PROPERTIES C_VISIBILITY_PRESET hidden)
    SET_TARGET_PROPERTIES(urpc PROPERTIES CXX_VISIBILITY_PRESET hidden)
    SET_TARGET_PROPERTIES(urpc PROPERTIES VISIBILITY_INLINES_HIDDEN TRUE)
ENDIF()

FUNCTION(ADD_SUBDIRECTORY_ZF_LOG)
    SET(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
    GET_DIRECTORY_PROPERTY(HAS_PARENT PARENT_DIRECTORY)
    IF(NOT HAS_PARENT)
        SET(ZF_LOG_LIBRARY_PREFIX "urpc_" CACHE INTERNAL "")
        SET(ZF_LOG_OPTIMIZE_SIZE ON CACHE INTERNAL "")
    ELSE()
        add_definitions(-DZF_LOG_EXTERN_GLOBAL_OUTPUT_LEVEL)
    ENDIF()
    ADD_SUBDIRECTORY(vendor/zf_log/zf_log)
    if (HAS_PARENT)
        remove_definitions(-DZF_LOG_EXTERN_GLOBAL_OUTPUT_LEVEL)
    ENDIF()
ENDFUNCTION()
ADD_SUBDIRECTORY_ZF_LOG()
# Make zf_log.h available for all submodules
INCLUDE_DIRECTORIES(vendor/zf_log/zf_log)
TARGET_LINK_LIBRARIES(urpc zf_log)

if(MSVC)
     target_compile_options(urpc PRIVATE /W3 /WX)
else()
     target_compile_options(urpc PRIVATE -Wall -Wextra -Werror)
endif()

FUNCTION(ADD_SUBDIRECTORY_TINYCTHREAD)
    SET(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
    SET(TINYCTHREAD_DISABLE_TESTS ON CACHE INTERNAL "")
    SET(TINYCTHREAD_INSTALL OFF CACHE INTERNAL "")
    ADD_SUBDIRECTORY(vendor/tinycthread)
ENDFUNCTION()
ADD_SUBDIRECTORY_TINYCTHREAD()
target_include_directories(urpc PRIVATE vendor/tinycthread/source)
TARGET_LINK_LIBRARIES(urpc tinycthread)

IF(URPC_ENABLE_SERIAL)
    ADD_SUBDIRECTORY(devserial)
    TARGET_LINK_LIBRARIES(urpc urpc-serial)
ENDIF()

IF(URPC_ENABLE_UDP)
    ADD_SUBDIRECTORY(devudp)
    TARGET_LINK_LIBRARIES(urpc urpc-udp)
ENDIF()

IF(URPC_ENABLE_XINET)
    if (NOT DEFINED XIBRIDGE_PATH)
    
    
        if (NOT DEFINED XIBRIDGE_VER)
           set(XIBRIDGE_VER "1.1.0")
        endif()
        message (${XIBRIDGE_VER})
        file(DOWNLOAD
           https://github.com/EPC-MSU/xibridge/releases/download/v${XIBRIDGE_VER}/xibridge-${XIBRIDGE_VER}.zip
           ${CMAKE_BINARY_DIR}/vendor/xibridge/xibridge-${XIBRIDGE_VER}.zip
           STATUS DOWNLOAD_STATUS
        )
        # Separate the returned status code, and error message.
        list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
        list(GET DOWNLOAD_STATUS 1 ERROR_MESSAGE)
        # Check if download was successful. 
        if(${STATUS_CODE} EQUAL 0)
            message(STATUS "Download completed successfully!")
        else()
       # Exit CMake if the download failed, printing the error message.
           message(FATAL_ERROR "Error occurred during download: ${ERROR_MESSAGE}")
        endif()
    
        execute_process(
           COMMAND ${CMAKE_COMMAND} -E tar xzf ${CMAKE_BINARY_DIR}/vendor/xibridge/xibridge-${XIBRIDGE_VER}.zip
           WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/vendor/xibridge
         )     
   
         if(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
            set (XIBRIDGE_PATH "${CMAKE_BINARY_DIR}/vendor/xibridge/macos" CACHE INTERNAL "")
         elseif(${CMAKE_SYSTEM_NAME} STREQUAL Windows)
            if (CMAKE_SIZEOF_VOID_P EQUAL 8)
                # 64 bits
                set (XIBRIDGE_PATH "${CMAKE_BINARY_DIR}/vendor/xibridge/win64"  CACHE INTERNAL "")
            else()
                # 32 bits
                set (XIBRIDGE_PATH "${CMAKE_BINARY_DIR}/vendor/xibridge/win32" CACHE INTERNAL "")
            endif()      
         else()       
            set (XIBRIDGE_PATH "${CMAKE_BINARY_DIR}/vendor/xibridge/deb64" CACHE INTERNAL "")
         endif()
     endif()
     find_path(XIBRIDGE_INCLUDE_DIR xibridge.h PATHS ${XIBRIDGE_PATH})
     find_library(XIBRIDGE_LIBRARY NAMES xibridge PATHS  ${XIBRIDGE_PATH} ${XIBRIDGE_PATH}/Debug ${XIBRIDGE_PATH}/Release)
     include(FindPackageHandleStandardArgs)
     FIND_PACKAGE_HANDLE_STANDARD_ARGS(XIBRIDGE DEFAULT_MSG XIBRIDGE_INCLUDE_DIR XIBRIDGE_LIBRARY)
     mark_as_advanced(XIBRIDGE_INCLUDE_DIR XIBRIDGE_LIBRARY)
     if(NOT XIBRIDGE_FOUND)
         message(FATAL_ERROR "xibridge could not be found in XIBRIDGE_PATH")
     else ()
     include_directories(${XIBRIDGE_INCLUDE_DIR})
     target_link_libraries(urpc ${XIBRIDGE_LIBRARY})
   endif()
ENDIF()


 