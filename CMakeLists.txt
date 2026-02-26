cmake_minimum_required(VERSION 3.16)
project(OpenIpScanner VERSION 0.1.0 LANGUAGES CXX)

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

target_link_libraries(open_ip_scanner PRIVATE
    ${QT_PACKAGE}::Widgets
    ${QT_PACKAGE}::Network
    ${QT_PACKAGE}::Concurrent
    ${QT_PACKAGE}::PrintSupport
)

install(TARGETS open_ip_scanner
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
    resources/linux/open-ip-scanner.desktop
    resources/linux/open_ip_scanner.desktop
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/applications
)

install(FILES
    resources/app_icon.svg
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps
    RENAME open-ip-scanner.svg
)

install(FILES
    resources/app_icon.svg
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps
    RENAME open_ip_scanner.svg
)

install(FILES
    resources/app_icon.svg
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pixmaps
    RENAME open-ip-scanner.svg
)

install(FILES
    resources/app_icon.svg
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pixmaps
    RENAME open_ip_scanner.svg
)

install(FILES
    resources/linux/open-ip-scanner.metainfo.xml
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/metainfo
)

set(CPACK_PACKAGE_NAME "open-ip-scanner")
set(CPACK_PACKAGE_VENDOR "Open IP Scanner")
set(CPACK_PACKAGE_CONTACT "maintainer@example.com")
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
