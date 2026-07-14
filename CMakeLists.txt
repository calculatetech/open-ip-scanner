cmake_minimum_required(VERSION 3.28)
project(OpenIpScanner VERSION 0.5.13 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

include(GNUInstallDirs)

find_package(Qt6 6.4 REQUIRED COMPONENTS
    Core Widgets Network PrintSupport DBus)

add_library(ois_core STATIC
    src/csvexporter.h
    src/csvexporter.cpp
    src/hostnameevidence.h
    src/hostnameevidence.cpp
    src/neighborentry.h
    src/neighborentry.cpp
    src/ouidatabase.h
    src/ouidatabase.cpp
    src/resolverdiagnostics.h
    src/resolverdiagnostics.cpp
    src/scanbudget.h
    src/serviceevidence.h
    src/serviceevidence.cpp
    src/settingsstore.h
    src/settingsstore.cpp
    src/targetparser.h
    src/targetparser.cpp
    src/targetdefaults.h
    src/targetdefaults.cpp
)
target_include_directories(ois_core PUBLIC src)
target_link_libraries(ois_core PUBLIC Qt6::Core Qt6::Network)

add_library(ois_scan STATIC
    src/debugscanfixture.h
    src/debugscanfixture.cpp
    src/scanengine.h
    src/scanengine.cpp
    src/productionhostscanbackend.h
    src/productionhostscanbackend.cpp
    src/scanoptions.h
    src/scanresult.h
    src/scansession.h
    src/scansession.cpp
)
target_include_directories(ois_scan PUBLIC src)
target_link_libraries(ois_scan PUBLIC ois_core Qt6::Core Qt6::Network)

add_library(ois_linux STATIC
    src/cancellablewait.h
    src/cancellablewait.cpp
    src/linuxneighborprobe.h
    src/linuxneighborprobe.cpp
    src/mdnsresolver.h
    src/mdnsresolver.cpp
)
target_include_directories(ois_linux PUBLIC src)
target_link_libraries(ois_linux
    PUBLIC ois_core Qt6::Core Qt6::Network
    PRIVATE Qt6::DBus)

add_library(ois_ui STATIC
    src/resulttablemodel.h
    src/resulttablemodel.cpp
    src/servicetagdelegate.h
    src/servicetagdelegate.cpp
    src/settingslayout.h
    src/scannerwindow.h
    src/scannerwindow.cpp
)
target_include_directories(ois_ui PUBLIC src)
target_link_libraries(ois_ui PUBLIC
    ois_core ois_scan ois_linux
    Qt6::Widgets Qt6::Network Qt6::PrintSupport Qt6::DBus)
target_compile_definitions(ois_ui PUBLIC
    OPEN_IP_SCANNER_VERSION="${PROJECT_VERSION}")

add_executable(open_ip_scanner
    src/main.cpp
    resources/resources.qrc
)
target_link_libraries(open_ip_scanner PRIVATE ois_ui)

include(CTest)
option(OIS_MDNS_CONTROLLED_FIXTURE
       "Enable the isolated Avahi controlled-responder CTest"
       OFF)

if(BUILD_TESTING)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
    add_executable(csv_exporter_test tests/csvexporter_test.cpp)
    target_link_libraries(csv_exporter_test PRIVATE ois_core)
    add_test(NAME csv_exporter_contract COMMAND csv_exporter_test)

    add_executable(mdns_resolver_test tests/mdnsresolver_test.cpp)
    target_link_libraries(mdns_resolver_test PRIVATE ois_linux Qt6::DBus)
    add_test(NAME mdns_resolver_contract COMMAND mdns_resolver_test)

    add_executable(mdns_integration_test tests/mdnsintegration_test.cpp)
    target_link_libraries(mdns_integration_test PRIVATE ois_linux)
    if(OIS_MDNS_CONTROLLED_FIXTURE)
        add_test(NAME mdns_controlled_responder
                 COMMAND mdns_integration_test
                         --interface ois0
                         --address 10.77.0.2
                         --hostname fixture.local)
    endif()

    add_executable(enrichment_provenance_test tests/enrichmentprovenance_test.cpp)
    target_link_libraries(enrichment_provenance_test PRIVATE ois_core)
    add_test(NAME enrichment_provenance_contract COMMAND enrichment_provenance_test)

    add_executable(debug_scan_fixture_test tests/debugscanfixture_test.cpp)
    target_link_libraries(debug_scan_fixture_test PRIVATE ois_core ois_scan)
    add_test(NAME debug_scan_fixture_contract COMMAND debug_scan_fixture_test)

    add_executable(scan_options_test tests/scanoptions_test.cpp)
    target_link_libraries(scan_options_test PRIVATE ois_scan)
    add_test(NAME scan_options_snapshot_isolation COMMAND scan_options_test)

    add_executable(scan_session_test tests/scansession_test.cpp)
    target_link_libraries(scan_session_test PRIVATE ois_scan)
    add_test(NAME scan_session_lifecycle COMMAND scan_session_test)

    add_executable(scan_engine_test tests/scanengine_test.cpp)
    target_link_libraries(scan_engine_test PRIVATE ois_scan)
    add_test(NAME scan_engine_scheduling COMMAND scan_engine_test)

    add_executable(production_host_backend_test
        tests/productionhostscanbackend_test.cpp)
    target_link_libraries(production_host_backend_test PRIVATE ois_scan)
    add_test(NAME production_host_backend_contract
        COMMAND production_host_backend_test)

    add_executable(scan_cancellation_test tests/scancancellation_test.cpp)
    target_link_libraries(scan_cancellation_test PRIVATE ois_linux)
    add_test(NAME scan_cancellation_deadlines COMMAND scan_cancellation_test)

    add_executable(linux_neighbor_probe_test tests/linuxneighborprobe_test.cpp)
    target_link_libraries(linux_neighbor_probe_test PRIVATE ois_linux)
    add_test(NAME linux_neighbor_probe_contract COMMAND linux_neighbor_probe_test)

    add_executable(scan_budget_test tests/scanbudget_test.cpp)
    target_link_libraries(scan_budget_test PRIVATE ois_scan)
    add_test(NAME scan_budget_profiles COMMAND scan_budget_test)

    add_executable(settings_layout_test tests/settingslayout_test.cpp)
    target_link_libraries(settings_layout_test PRIVATE ois_ui)
    add_test(NAME settings_layout_contract COMMAND settings_layout_test)

    add_executable(target_defaults_test tests/targetdefaults_test.cpp)
    target_link_libraries(target_defaults_test PRIVATE ois_core)
    add_test(NAME target_default_planning COMMAND target_defaults_test)

    add_executable(target_parser_test tests/targetparser_test.cpp)
    target_link_libraries(target_parser_test PRIVATE ois_core)
    add_test(NAME target_parser_contract COMMAND target_parser_test)

    add_executable(core_policy_test tests/corepolicy_test.cpp)
    target_link_libraries(core_policy_test PRIVATE ois_core)
    add_test(NAME core_policy_contract COMMAND core_policy_test)

    add_executable(neighbor_entry_test tests/neighborentry_test.cpp)
    target_link_libraries(neighbor_entry_test PRIVATE ois_core)
    add_test(NAME neighbor_entry_validation COMMAND neighbor_entry_test)

    add_executable(service_evidence_test tests/serviceevidence_test.cpp)
    target_link_libraries(service_evidence_test PRIVATE ois_core)
    add_test(NAME service_evidence_classification COMMAND service_evidence_test)

    add_executable(settings_dialog_test
        tests/settingsdialog_test.cpp resources/resources.qrc)
    target_link_libraries(settings_dialog_test PRIVATE ois_ui Qt6::Test)
    add_test(NAME settings_dialog_stability COMMAND settings_dialog_test)
    set_tests_properties(settings_dialog_stability PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )
endif()

set_target_properties(open_ip_scanner PROPERTIES
    OUTPUT_NAME "open-ip-scanner"
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
