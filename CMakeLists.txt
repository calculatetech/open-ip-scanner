cmake_minimum_required(VERSION 3.16)
project(OpenIpScanner VERSION 0.5.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

include(GNUInstallDirs)

find_package(Qt6 QUIET COMPONENTS Widgets Network Concurrent PrintSupport DBus)
if (Qt6_FOUND)
    set(QT_PACKAGE Qt6)
else()
    find_package(Qt5 REQUIRED COMPONENTS Widgets Network Concurrent PrintSupport DBus)
    set(QT_PACKAGE Qt5)
endif()

add_executable(open_ip_scanner
    src/main.cpp
    src/cancellablewait.h
    src/cancellablewait.cpp
    src/debugscanfixture.h
    src/debugscanfixture.cpp
    src/hostnameevidence.h
    src/hostnameevidence.cpp
    src/mdnsresolver.h
    src/mdnsresolver.cpp
    src/neighborentry.h
    src/neighborentry.cpp
    src/scanbudget.h
    src/scanoptions.h
    src/scanresult.h
    src/resulttablemodel.h
    src/resulttablemodel.cpp
    src/resolverdiagnostics.h
    src/resolverdiagnostics.cpp
    src/serviceevidence.h
    src/serviceevidence.cpp
    src/servicetagdelegate.h
    src/servicetagdelegate.cpp
    src/settingslayout.h
    src/targetdefaults.h
    src/targetdefaults.cpp
    src/scannerwindow.h
    src/scannerwindow.cpp
    resources/resources.qrc
)

include(CTest)
option(OIS_MDNS_CONTROLLED_FIXTURE
       "Enable the isolated Avahi controlled-responder CTest"
       OFF)

if(BUILD_TESTING)
    add_executable(mdns_resolver_test
        tests/mdnsresolver_test.cpp
        src/cancellablewait.h
        src/cancellablewait.cpp
        src/hostnameevidence.h
        src/hostnameevidence.cpp
        src/mdnsresolver.h
        src/mdnsresolver.cpp
    )
    target_include_directories(mdns_resolver_test PRIVATE src)
    target_link_libraries(mdns_resolver_test PRIVATE
        ${QT_PACKAGE}::Core
        ${QT_PACKAGE}::Network
        ${QT_PACKAGE}::DBus
    )
    add_test(NAME mdns_resolver_contract COMMAND mdns_resolver_test)

    add_executable(mdns_integration_test
        tests/mdnsintegration_test.cpp
        src/cancellablewait.h
        src/cancellablewait.cpp
        src/hostnameevidence.h
        src/hostnameevidence.cpp
        src/mdnsresolver.h
        src/mdnsresolver.cpp
    )
    target_include_directories(mdns_integration_test PRIVATE src)
    target_link_libraries(mdns_integration_test PRIVATE
        ${QT_PACKAGE}::Core
        ${QT_PACKAGE}::Network
        ${QT_PACKAGE}::DBus
    )
    if(OIS_MDNS_CONTROLLED_FIXTURE)
        add_test(NAME mdns_controlled_responder
                 COMMAND mdns_integration_test
                         --interface ois0
                         --address 10.77.0.2
                         --hostname fixture.local)
    endif()

    add_executable(enrichment_provenance_test
        tests/enrichmentprovenance_test.cpp
        src/hostnameevidence.h
        src/hostnameevidence.cpp
        src/resolverdiagnostics.h
        src/resolverdiagnostics.cpp
    )
    target_include_directories(enrichment_provenance_test PRIVATE src)
    target_link_libraries(enrichment_provenance_test PRIVATE
        ${QT_PACKAGE}::Core
        ${QT_PACKAGE}::Network
    )
    add_test(NAME enrichment_provenance_contract COMMAND enrichment_provenance_test)

    add_executable(debug_scan_fixture_test
        tests/debugscanfixture_test.cpp
        src/debugscanfixture.h
        src/debugscanfixture.cpp
        src/neighborentry.h
        src/neighborentry.cpp
        src/scanresult.h
        src/serviceevidence.h
        src/serviceevidence.cpp
    )
    target_include_directories(debug_scan_fixture_test PRIVATE src)
    target_link_libraries(debug_scan_fixture_test PRIVATE ${QT_PACKAGE}::Core ${QT_PACKAGE}::Network)
    add_test(NAME debug_scan_fixture_contract COMMAND debug_scan_fixture_test)

    add_executable(scan_options_test
        tests/scanoptions_test.cpp
        src/scanoptions.h
    )
    target_include_directories(scan_options_test PRIVATE src)
    target_link_libraries(scan_options_test PRIVATE ${QT_PACKAGE}::Core)
    add_test(NAME scan_options_snapshot_isolation COMMAND scan_options_test)

    add_executable(scan_cancellation_test
        tests/scancancellation_test.cpp
        src/cancellablewait.h
        src/cancellablewait.cpp
        src/hostnameevidence.h
        src/hostnameevidence.cpp
    )
    target_include_directories(scan_cancellation_test PRIVATE src)
    target_link_libraries(scan_cancellation_test PRIVATE ${QT_PACKAGE}::Core ${QT_PACKAGE}::Network)
    add_test(NAME scan_cancellation_deadlines COMMAND scan_cancellation_test)

    add_executable(scan_budget_test tests/scanbudget_test.cpp)
    target_include_directories(scan_budget_test PRIVATE src)
    add_test(NAME scan_budget_profiles COMMAND scan_budget_test)

    add_executable(settings_layout_test tests/settingslayout_test.cpp)
    target_include_directories(settings_layout_test PRIVATE src)
    add_test(NAME settings_layout_contract COMMAND settings_layout_test)

    add_executable(target_defaults_test
        tests/targetdefaults_test.cpp
        src/targetdefaults.h
        src/targetdefaults.cpp
    )
    target_include_directories(target_defaults_test PRIVATE src)
    target_link_libraries(target_defaults_test PRIVATE ${QT_PACKAGE}::Network)
    add_test(NAME target_default_planning COMMAND target_defaults_test)

    add_executable(neighbor_entry_test
        tests/neighborentry_test.cpp
        src/neighborentry.h
        src/neighborentry.cpp
    )
    target_include_directories(neighbor_entry_test PRIVATE src)
    target_link_libraries(neighbor_entry_test PRIVATE ${QT_PACKAGE}::Network)
    add_test(NAME neighbor_entry_validation COMMAND neighbor_entry_test)

    add_executable(service_evidence_test
        tests/serviceevidence_test.cpp
        src/serviceevidence.h
        src/serviceevidence.cpp
    )
    target_include_directories(service_evidence_test PRIVATE src)
    target_link_libraries(service_evidence_test PRIVATE ${QT_PACKAGE}::Core)
    add_test(NAME service_evidence_classification COMMAND service_evidence_test)

    add_executable(settings_dialog_test
        tests/settingsdialog_test.cpp
        src/cancellablewait.h
        src/cancellablewait.cpp
        src/debugscanfixture.h
        src/debugscanfixture.cpp
        src/hostnameevidence.h
        src/hostnameevidence.cpp
        src/mdnsresolver.h
        src/mdnsresolver.cpp
        src/neighborentry.h
        src/neighborentry.cpp
        src/scanbudget.h
        src/scanoptions.h
        src/scanresult.h
        src/resulttablemodel.h
        src/resulttablemodel.cpp
        src/resolverdiagnostics.h
        src/resolverdiagnostics.cpp
        src/serviceevidence.h
        src/serviceevidence.cpp
        src/servicetagdelegate.h
        src/servicetagdelegate.cpp
        src/settingslayout.h
        src/targetdefaults.h
        src/targetdefaults.cpp
        src/scannerwindow.h
        src/scannerwindow.cpp
        resources/resources.qrc
    )
    target_include_directories(settings_dialog_test PRIVATE src)
    target_link_libraries(settings_dialog_test PRIVATE
        ${QT_PACKAGE}::Widgets
        ${QT_PACKAGE}::Network
        ${QT_PACKAGE}::Concurrent
        ${QT_PACKAGE}::PrintSupport
        ${QT_PACKAGE}::DBus
    )
    target_compile_definitions(settings_dialog_test PRIVATE
        OPEN_IP_SCANNER_VERSION="${PROJECT_VERSION}"
    )
    add_test(NAME settings_dialog_stability COMMAND settings_dialog_test)
    set_tests_properties(settings_dialog_stability PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )
endif()

set_target_properties(open_ip_scanner PROPERTIES
    OUTPUT_NAME "open-ip-scanner"
)

target_link_libraries(open_ip_scanner PRIVATE
    ${QT_PACKAGE}::Widgets
    ${QT_PACKAGE}::Network
    ${QT_PACKAGE}::Concurrent
    ${QT_PACKAGE}::PrintSupport
    ${QT_PACKAGE}::DBus
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
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "avahi-daemon")

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
