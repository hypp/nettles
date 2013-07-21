cmake_minimum_required (VERSION 2.8)
project (Nettles)

include(ExternalProject)
include (CheckFunctionExists)

CHECK_FUNCTION_EXISTS(stricmp HAVE_STRICMP)
CHECK_FUNCTION_EXISTS(_stricmp HAVE__STRICMP)
CHECK_FUNCTION_EXISTS(strcasecmp HAVE_STRCASECMP)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/src/config.h)

SET(LuaMakeArg "")
SET(PlatformExtraLibs "")
IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
   SET(LuaMakeArg "macosx")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
   SET(LuaMakeArg "linux")
   SET(PlatformExtraLibs m rt)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
IF(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
   SET(LuaMakeArg "mingw")
   SET(PlatformExtraLibs ws2_32)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

ExternalProject_Add(
  libevent-2.0.21
  PREFIX deps/
  URL ${CMAKE_CURRENT_SOURCE_DIR}/deps/libevent-2.0.21-stable.tar.gz
  CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>
--disable-shared --disable-openssl  
)
SET(libeventLibs event_core event_extra)

ExternalProject_Add(
  lua-5.2.2
  PREFIX deps/
  URL ${CMAKE_CURRENT_SOURCE_DIR}/deps/lua-5.2.2.tar.gz
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make ${LuaMakeArg}
  INSTALL_COMMAND make install INSTALL_TOP=<INSTALL_DIR>
)
SET(luaLibs lua)

ExternalProject_Add(
  polarssl-1.2.8
  PREFIX deps/
  URL ${CMAKE_CURRENT_SOURCE_DIR}/deps/polarssl-1.2.8-gpl.tgz
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
SET(polarsslLibs polarssl)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/lib)

set(SOURCES src/cleartext_stream.c  src/listener.c  src/nettles.c
src/ssl_stream.c  src/stream.c)

add_executable(nettles ${SOURCES})
add_dependencies(nettles libevent-2.0.21 lua-5.2.2 polarssl-1.2.8)
target_link_libraries(nettles ${libeventLibs} ${luaLibs} ${polarsslLibs}
${PlatformExtraLibs})

set(CPACK_PACKAGE_NAME "nettles")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 2)
set(CPACK_PACKAGE_VERSION_PATCH 0)

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Mathias Olsson")

install(TARGETS nettles RUNTIME DESTINATION ${CPACK_PACKAGE_NAME}/bin)
install(FILES examples/client-nettles.lua examples/server-nettles.lua DESTINATION /etc/${CPACK_PACKAGE_NAME})

include(CPack)

