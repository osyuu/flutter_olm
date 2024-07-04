# Install script for directory: /Users/phil/shaberi/flutter_olm-1.4.1/ios

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "0")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "TRUE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Users/phil/Library/Android/sdk/ndk/21.4.7075529/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android-objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/phil/shaberi/flutter_olm-1.4.1/android/.cxx/Debug/3i92ug4f/x86/libolm.so")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libolm.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libolm.so")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Users/phil/Library/Android/sdk/ndk/21.4.7075529/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android-strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libolm.so")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/olm" TYPE FILE FILES
    "/Users/phil/shaberi/flutter_olm-1.4.1/ios/include/olm/olm.h"
    "/Users/phil/shaberi/flutter_olm-1.4.1/ios/include/olm/olm_export.h"
    "/Users/phil/shaberi/flutter_olm-1.4.1/ios/include/olm/outbound_group_session.h"
    "/Users/phil/shaberi/flutter_olm-1.4.1/ios/include/olm/inbound_group_session.h"
    "/Users/phil/shaberi/flutter_olm-1.4.1/ios/include/olm/pk.h"
    "/Users/phil/shaberi/flutter_olm-1.4.1/ios/include/olm/sas.h"
    "/Users/phil/shaberi/flutter_olm-1.4.1/ios/include/olm/error.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/Users/phil/shaberi/flutter_olm-1.4.1/android/.cxx/Debug/3i92ug4f/x86/olm.pc")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/Olm/OlmTargets.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/Olm/OlmTargets.cmake"
         "/Users/phil/shaberi/flutter_olm-1.4.1/android/.cxx/Debug/3i92ug4f/x86/CMakeFiles/Export/lib/cmake/Olm/OlmTargets.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/Olm/OlmTargets-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/Olm/OlmTargets.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/Olm" TYPE FILE FILES "/Users/phil/shaberi/flutter_olm-1.4.1/android/.cxx/Debug/3i92ug4f/x86/CMakeFiles/Export/lib/cmake/Olm/OlmTargets.cmake")
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/Olm" TYPE FILE FILES "/Users/phil/shaberi/flutter_olm-1.4.1/android/.cxx/Debug/3i92ug4f/x86/CMakeFiles/Export/lib/cmake/Olm/OlmTargets-debug.cmake")
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/Olm" TYPE FILE FILES
    "/Users/phil/shaberi/flutter_olm-1.4.1/android/.cxx/Debug/3i92ug4f/x86/OlmConfig.cmake"
    "/Users/phil/shaberi/flutter_olm-1.4.1/android/.cxx/Debug/3i92ug4f/x86/OlmConfigVersion.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/Users/phil/shaberi/flutter_olm-1.4.1/android/.cxx/Debug/3i92ug4f/x86/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
