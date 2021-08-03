include(FetchContent)

cmake_minimum_required(VERSION 3.10)

project(yocto-tls)

FetchContent_Declare(
  libtomcrypt
  GIT_REPOSITORY https://github.com/libtom/libtomcrypt
  GIT_TAG        v1.18.2
)

FetchContent_Declare(
  libtommath
  GIT_REPOSITORY https://github.com/libtom/libtommath
  GIT_TAG        v1.2.0
)

FetchContent_Declare(sockpp
    GIT_REPOSITORY https://github.com/fpagliughi/sockpp
    GIT_TAG        v0.7
)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.4)

FetchContent_MakeAvailable(libtomcrypt libtommath sockpp Catch2)

add_library(yocto-tls-libtomcrypt)
add_library(yocto-tls-libtommath)
add_library(yocto-tls-sockpp)
add_library(yocto-tls-lib)
add_library(yocto-tls-lib-fixed-random)
add_executable(yocto-tls-client-example)
add_executable(yocto-tls-server-example)
add_executable(yocto-tls-unit-test)

target_include_directories(yocto-tls-libtomcrypt PUBLIC "${libtomcrypt_SOURCE_DIR}/src/headers")
file(GLOB yocto-tls-libtomcrypt-header-files "${libtomcrypt_SOURCE_DIR}/src/headers/*.h")
file(GLOB_RECURSE  yocto-tls-libtomcrypt-source-files "${libtomcrypt_SOURCE_DIR}/src/*.c")
target_sources(yocto-tls-libtomcrypt PRIVATE ${yocto-tls-libtomcrypt-source-files} ${yocto-tls-libtomcrypt-header-files})
target_compile_definitions(yocto-tls-libtomcrypt PUBLIC LTM_DESC LTC_SOURCE LTC_NO_TEST LTC_NO_PROTOTYPES)
target_link_libraries(yocto-tls-libtomcrypt yocto-tls-libtommath)

target_include_directories(yocto-tls-libtommath PUBLIC "${libtommath_SOURCE_DIR}")
file(GLOB yocto-tls-libtommath-header-files "${libtommath_SOURCE_DIR}/*.h")
file(GLOB yocto-tls-libtommath-source-files "${libtommath_SOURCE_DIR}/*.c")
target_sources(yocto-tls-libtommath PRIVATE ${yocto-tls-libtommath-source-files} ${yocto-tls-libtommath-header-files})

target_include_directories(yocto-tls-sockpp PUBLIC "${sockpp_SOURCE_DIR}/include")
file(GLOB yocto-tls-sockpp-header-files "${sockpp_SOURCE_DIR}/include/*.h")
file(GLOB yocto-tls-sockpp-source-files "${sockpp_SOURCE_DIR}/src/*.cpp")
target_sources(yocto-tls-sockpp PRIVATE ${yocto-tls-sockpp-source-files} ${yocto-tls-sockpp-header-files})

target_include_directories(yocto-tls-lib PUBLIC "./inc" "./inc/tomcrypt")
target_sources(yocto-tls-lib PRIVATE "./src/tls.c" "./src/tomcrypt/cal.c" "./src/tomcrypt/osal.c" "./inc/tls.h" "./inc/tomcrypt/cal.h" "./inc/osal.h")
target_link_libraries(yocto-tls-lib yocto-tls-libtomcrypt)

target_include_directories(yocto-tls-lib-fixed-random PUBLIC "./inc" "./inc/tomcrypt")
target_sources(yocto-tls-lib-fixed-random PRIVATE "./src/tls.c" "./src/tomcrypt/cal.c" "./src/tomcrypt/osal.c" "./inc/tls.h" "./inc/tomcrypt/cal.h" "./inc/osal.h")
target_compile_definitions(yocto-tls-lib-fixed-random PRIVATE FIXED_RANDOM_FOR_TESTING_ONLY)
target_link_libraries(yocto-tls-lib-fixed-random yocto-tls-libtomcrypt)

target_sources(yocto-tls-client-example PRIVATE "./example/client-example.cpp")
target_link_libraries(yocto-tls-client-example yocto-tls-lib yocto-tls-sockpp)
if (WIN32)
target_link_libraries(yocto-tls-client-example Ws2_32.lib)
endif()

target_sources(yocto-tls-server-example PRIVATE "./example/server-example.cpp")
target_link_libraries(yocto-tls-server-example yocto-tls-lib yocto-tls-sockpp)
if (WIN32)
target_link_libraries(yocto-tls-server-example Ws2_32.lib)
endif()

target_sources(yocto-tls-unit-test PRIVATE "./test/catch2/unit-test.cpp")
target_link_libraries(yocto-tls-unit-test PRIVATE Catch2::Catch2 yocto-tls-lib-fixed-random)




