cmake_minimum_required(VERSION 3.20)
project(ngx_http_auth_jwt_module C)

set (TARGET_NAME "${PROJECT_NAME}")

set(CMAKE_C_STANDARD 99)
set (LIBRARY_TYPE SHARED)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

#find_library(LIBJWT_LIBRARY NAMES libjwt REQUIRED)

add_library(${TARGET_NAME} ${LIBRARY_TYPE}
        ngx_http_auth_jwt_module.c
        ngx_http_auth_jwt_module_modules.g.c)

file(STRINGS ${PROJECT_SOURCE_DIR}/CONFIG.txt ConfigContents)
foreach(NameAndValue ${ConfigContents})
    string(REGEX REPLACE "^[ ]+" "" NameAndValue ${NameAndValue})
    string(REGEX MATCH "^[^=]+" Name ${NameAndValue})
    string(REPLACE "${Name}=" "" Value ${NameAndValue})
    set(${Name} "${Value}")
endforeach()

set(NGINX_INCLUDE_DIR
        "${NGINX_PATH}/objs"
        "${NGINX_PATH}/src/core"
        "${NGINX_PATH}/src/event"
        "${NGINX_PATH}/src/http"
        "${NGINX_PATH}/src/http/v2"
        "${NGINX_PATH}/src/http/modules"
        "${NGINX_PATH}/src/os/unix"
        )

set(NGINX_LIBRARY_DIR
        "${NGINX_PATH}/objs")

set(LIBJWT_INCLUDE_DIR
        "${LIBJWT_PATH}/include")

set (LIBJWT_LIBRARY_DIR
        "${LIBJWT_PATH}/build/libjwt")

set (LIBJANSSON_INCLUDE_DIR
        "${LIBJANSSON_PATH}/build/include")

set (LIBJANSSON_LIBRARY_DIR
        "${LIBJANSSON_PATH}/build/lib")

target_include_directories(${TARGET_NAME} PUBLIC
        ${NGINX_INCLUDE_DIR}
        ${LIBJWT_INCLUDE_DIR}
        ${LIBJANSSON_INCLUDE_DIR}
        )

target_link_directories(${TARGET_NAME} PUBLIC
        ${NGINX_LIBRARY_DIR}
        ${LIBJWT_LIBRARY_DIR}
        ${LIBJANSSON_LIBRARY_DIR}
        )

target_link_libraries(${TARGET_NAME}
        -ljwt
        -ljansson
        )

set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "")
