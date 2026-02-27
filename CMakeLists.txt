cmake_minimum_required(VERSION 3.16)
project(OpenIpScanner VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

include(GNUInstallDirs)

find_package(Qt6 QUIET COMPONENTS Widgets Network Concurrent PrintSupport)
if (Qt6_FOUND)
    set(QT_PACKAGE Qt6)
else()
    find_package(Qt5 REQUIRED COMPONENTS Widgets Network Concurrent PrintSupport)
    set(QT_PACKAGE Qt5)
endif()

add_executable(open_ip_scanner
    src/main.cpp
    src/scannerwindow.h
    src/scannerwindow.cpp
    resources/resources.qrc
)

set_target_properties(open_ip_scanner PROPERTIES
    OUTPUT_NAME "open-ip-scanner"
)

target_link_libraries(open_ip_scanner PRIVATE
    ${QT_PACKAGE}::Widgets
    ${QT_PACKAGE}::Network
    ${QT_PACKAGE}::Concurrent
    ${QT_PACKAGE}::PrintSupport
)

target_compile_definitions(open_ip_scanner PRIVATE
    OPEN_IP_SCANNER_VERSION="${PROJECT_VERSION}"
)

install(TARGETS open_ip_scanner
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
    resources/linux/open-ip-scanner.desktop
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/applications
)

install(FILES
    resources/app_icon.svg
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps
    RENAME open-ip-scanner.svg
)

install(FILES
    resources/app_icon.svg
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pixmaps
    RENAME open-ip-scanner.svg
)

install(FILES
    resources/linux/open-ip-scanner.metainfo.xml
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/metainfo
)

# Cleanup legacy underscore-named integration files from older installs.
install(CODE [[
  file(REMOVE
    "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/applications/open_ip_scanner.desktop"
    "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps/open_ip_scanner.svg"
    "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/pixmaps/open_ip_scanner.svg")
]])

# Best-effort desktop cache refresh for local installs.
install(CODE [[
  if("$ENV{DESTDIR}" STREQUAL "")
    set(_apps_dir "${CMAKE_INSTALL_FULL_DATAROOTDIR}/applications")
    find_program(UPDATE_DESKTOP_DATABASE update-desktop-database)
    if(UPDATE_DESKTOP_DATABASE AND EXISTS "${_apps_dir}")
      execute_process(COMMAND "${UPDATE_DESKTOP_DATABASE}" "${_apps_dir}")
    endif()
    find_program(KBUILDSYCOCA6 kbuildsycoca6)
    if(KBUILDSYCOCA6)
      execute_process(COMMAND "${KBUILDSYCOCA6}")
    endif()
  endif()
]])

set(CPACK_PACKAGE_NAME "open-ip-scanner")
set(CPACK_PACKAGE_VENDOR "Open IP Scanner")
set(CPACK_PACKAGE_CONTACT "mikebeutler84@gmail.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Qt-based IP address scanner")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "iputils-ping, iproute2")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "avahi-utils")

include(CPack)

configure_file(
    ${CMAKE_SOURCE_DIR}/cmake_uninstall.cmake.in
    ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
    @ONLY
)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
)

add_custom_target(uninstall-local
    COMMAND ${CMAKE_COMMAND}
        -DUNINSTALL_PREFIX=$ENV{HOME}/.local
        -P ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
)
