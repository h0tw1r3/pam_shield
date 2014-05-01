cmake_minimum_required(VERSION 2.8)

project(pam_shield)

set(PAM_SHIELD_VERSION_MAJOR 0)
set(PAM_SHIELD_VERSION_MINOR 9)
set(PAM_SHIELD_VERSION_PATCH 6)

set(CMAKE_BUILD_TYPE Release)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_FLAGS_DEBUG  "-g")
set(CMAKE_C_FLAGS_RELEASE "-O2")

if(NOT DEFINED sysconfdir)
    set(sysconfdir "/etc")
endif()
if(NOT DEFINED localstatedir)
    set(localstatedir "/var")
endif()
if(NOT DEFINED datarootdir)
    set(datarootdir "share")
endif()

if(NOT DEFINED DEFAULT_DBFILE)
    set(DEFAULT_DBFILE "${localstatedir}/lib/pam_shield/db")
endif()

set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake
  ${CMAKE_MODULE_PATH}
)
find_package(GDBM REQUIRED)
find_package(PAM REQUIRED)

message(STATUS ${PAM_MODULE_DIR})

list(LENGTH commondefs n)
list(APPEND commondefs "PAM_SHIELD_VERSION=\"${PAM_SHIELD_VERSION_MAJOR}.${PAM_SHIELD_VERSION_MINOR}.${PAM_SHIELD_VERSION_PATCH}\"")
list(APPEND commondefs "DEFAULT_CONFFILE=\"${sysconfdir}/security/shield.conf\"")
list(APPEND commondefs "DEFAULT_DBFILE=\"${DEFAULT_DBFILE}/\"")
list(APPEND commondefs "DEFAULT_TRIGGER_CMD=\"${CMAKE_INSTALL_PREFIX}/sbin/shield-trigger\"")

set(MODULE_SRC pam_shield.c)
set(SHARED_SRC pam_shield_lib.c)
set(PURGE_SRC shield_purge.c)

add_library(pam_shield MODULE ${SHARED_SRC} ${MODULE_SRC})
add_executable(shield-purge ${SHARED_SRC} ${PURGE_SRC})

set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "${commondefs}")
set_target_properties(pam_shield PROPERTIES PREFIX "")

target_link_libraries(pam_shield ${GDBM_LIBRARIES} ${PAM_LIBRARIES})
target_link_libraries(shield-purge ${GDBM_LIBRARIES})

file(GLOB trigger_SCRIPTS "${CMAKE_SOURCE_DIR}/scripts/*")

install(TARGETS pam_shield DESTINATION ${PAM_MODULE_DIR}/)
install(TARGETS shield-purge DESTINATION sbin/)
install(PROGRAMS ${trigger_SCRIPTS} DESTINATION sbin/)
install(DIRECTORY man/ DESTINATION "${datarootdir}/man/man8" FILES_MATCHING PATTERN "*.8")
install(DIRECTORY man/ DESTINATION "${datarootdir}/man/man5" FILES_MATCHING PATTERN "*.5")
install(DIRECTORY pam-configs DESTINATION "${datarootdir}")
install(DIRECTORY cron.daily/ DESTINATION "${sysconfdir}/cron.daily")
install(FILES shield.conf DESTINATION "${sysconfdir}/security/" COMPONENT config)
