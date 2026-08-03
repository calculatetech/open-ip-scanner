cmake_minimum_required(VERSION 3.28)
project(OpenIpScanner VERSION 1.0.1 LANGUAGES CXX)

include(cmake/Hardening.cmake)

set(OIS_APP_ID "io.github.calculatetech.OpenIpScanner")
set(OIS_GENERATED_RESOURCE_DIR "${CMAKE_BINARY_DIR}/generated-resources")
file(MAKE_DIRECTORY "${OIS_GENERATED_RESOURCE_DIR}")
find_program(GZIP_EXECUTABLE gzip REQUIRED)

function(ois_generate_deterministic_gzip input output)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${input}")
    execute_process(
        COMMAND "${GZIP_EXECUTABLE}" -9 -n -c "${input}"
        OUTPUT_FILE "${output}"
        RESULT_VARIABLE gzip_result)
    if(NOT gzip_result EQUAL 0)
        message(FATAL_ERROR "Failed to compress ${input}")
    endif()
endfunction()

configure_file(
    resources/linux/open-ip-scanner.desktop.in
    "${OIS_GENERATED_RESOURCE_DIR}/${OIS_APP_ID}.desktop"
    @ONLY)
configure_file(
    resources/linux/open-ip-scanner.metainfo.xml.in
    "${OIS_GENERATED_RESOURCE_DIR}/${OIS_APP_ID}.metainfo.xml"
    @ONLY)
configure_file(
    packaging/open-ip-scanner.1.in
    "${OIS_GENERATED_RESOURCE_DIR}/open-ip-scanner.1"
    @ONLY)
configure_file(
    packaging/debian/changelog.in
    "${OIS_GENERATED_RESOURCE_DIR}/changelog"
    @ONLY)
ois_generate_deterministic_gzip(
    "${OIS_GENERATED_RESOURCE_DIR}/changelog"
    "${OIS_GENERATED_RESOURCE_DIR}/changelog.gz")
ois_generate_deterministic_gzip(
    "${OIS_GENERATED_RESOURCE_DIR}/open-ip-scanner.1"
    "${OIS_GENERATED_RESOURCE_DIR}/open-ip-scanner.1.gz")

include(cmake/PlatformSupport.cmake)
ois_validate_platform("${CMAKE_SYSTEM_NAME}"
                      "${CMAKE_SYSTEM_PROCESSOR}"
                      "${CMAKE_SIZEOF_VOID_P}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

option(OIS_WARNINGS_AS_ERRORS "Enable strict project compiler warnings" OFF)
if(OIS_WARNINGS_AS_ERRORS AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
        -Wshadow -Wformat=2 -Werror)
endif()

include(GNUInstallDirs)

configure_file(
    cmake/write_uninstall_state.cmake.in
    ${CMAKE_BINARY_DIR}/write_uninstall_state.cmake
    @ONLY)

find_package(Qt6 6.4 REQUIRED COMPONENTS
    Core Widgets Network PrintSupport DBus)

add_library(ois_core STATIC
    src/diagnostics.h
    src/diagnostics.cpp
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
    src/hostnameresolver.h
    src/hostnameresolver.cpp
    src/linuxpingprobe.h
    src/linuxpingprobe.cpp
    src/mdnsresolver.h
    src/mdnsresolver.cpp
    src/serviceprobe.h
    src/serviceprobe.cpp
)
target_include_directories(ois_linux PUBLIC src)
target_link_libraries(ois_linux
    PUBLIC ois_core Qt6::Core Qt6::Network
    PRIVATE Qt6::DBus)

add_library(ois_runtime STATIC
    src/scanrunners.h
    src/scanrunners.cpp
)
target_include_directories(ois_runtime PUBLIC src)
target_link_libraries(ois_runtime PUBLIC ois_core ois_scan ois_linux)

add_library(ois_ui STATIC
    src/devicepresentation.h
    src/devicepresentation.cpp
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
    ois_core ois_scan ois_linux ois_runtime
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
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(
        NAME platform_supported_contract
        COMMAND ${CMAKE_COMMAND}
                -DOIS_TEST_SYSTEM_NAME=Linux
                -DOIS_TEST_SYSTEM_PROCESSOR=x86_64
                -DOIS_TEST_POINTER_SIZE=8
                -P ${CMAKE_SOURCE_DIR}/cmake/platform_contract_test.cmake)
    foreach(platform_case IN ITEMS non_linux non_x86_64 non_64_bit)
        if(platform_case STREQUAL "non_linux")
            set(test_system_name Windows)
            set(test_system_processor x86_64)
            set(test_pointer_size 8)
        elseif(platform_case STREQUAL "non_x86_64")
            set(test_system_name Linux)
            set(test_system_processor aarch64)
            set(test_pointer_size 8)
        else()
            set(test_system_name Linux)
            set(test_system_processor x86_64)
            set(test_pointer_size 4)
        endif()
        add_test(
            NAME platform_${platform_case}_rejected
            COMMAND ${CMAKE_COMMAND}
                    -DOIS_TEST_SYSTEM_NAME=${test_system_name}
                    -DOIS_TEST_SYSTEM_PROCESSOR=${test_system_processor}
                    -DOIS_TEST_POINTER_SIZE=${test_pointer_size}
                    -P ${CMAKE_SOURCE_DIR}/cmake/platform_contract_test.cmake)
        set_tests_properties(platform_${platform_case}_rejected
                             PROPERTIES WILL_FAIL TRUE)
    endforeach()

    add_executable(csv_exporter_test tests/csvexporter_test.cpp)
    target_link_libraries(csv_exporter_test PRIVATE ois_core)
    add_test(NAME csv_exporter_contract COMMAND csv_exporter_test)

    add_executable(diagnostics_test tests/diagnostics_test.cpp)
    target_link_libraries(diagnostics_test PRIVATE ois_core)
    add_test(NAME diagnostics_privacy_contract COMMAND diagnostics_test)

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

    add_executable(device_presentation_test tests/devicepresentation_test.cpp)
    target_link_libraries(device_presentation_test PRIVATE ois_ui)
    add_test(NAME device_presentation_contract COMMAND device_presentation_test)

    add_executable(result_table_model_test tests/resulttablemodel_test.cpp)
    target_link_libraries(result_table_model_test PRIVATE ois_ui)
    add_test(NAME result_search_evidence_contract COMMAND result_table_model_test)

    add_executable(service_tag_delegate_test tests/servicetagdelegate_test.cpp)
    target_link_libraries(service_tag_delegate_test PRIVATE ois_ui)
    add_test(NAME service_tag_theme_contract COMMAND service_tag_delegate_test)
    set_tests_properties(service_tag_theme_contract PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

    foreach(scale_factor IN ITEMS 1 2)
        add_test(NAME startup_accessibility_scale_${scale_factor}
            COMMAND ${CMAKE_COMMAND} -E env
                    --unset=QT_SCALE_FACTOR_ROUNDING_POLICY
                    QT_QPA_PLATFORM=offscreen
                    QT_SCALE_FACTOR=${scale_factor}
                    $<TARGET_FILE:open_ip_scanner> --startup-smoke)
        set_tests_properties(startup_accessibility_scale_${scale_factor} PROPERTIES
            FAIL_REGULAR_EXPRESSION
                "setHighDpiScaleFactorRoundingPolicy;must be called before creating"
            TIMEOUT 10)
    endforeach()

    add_executable(scan_cancellation_test tests/scancancellation_test.cpp)
    target_link_libraries(scan_cancellation_test PRIVATE ois_linux)
    add_test(NAME scan_cancellation_deadlines COMMAND scan_cancellation_test)

    add_executable(linux_neighbor_probe_test tests/linuxneighborprobe_test.cpp)
    target_link_libraries(linux_neighbor_probe_test PRIVATE ois_linux)
    add_test(NAME linux_neighbor_probe_contract COMMAND linux_neighbor_probe_test)

    add_executable(linux_ping_probe_test tests/linuxpingprobe_test.cpp)
    target_link_libraries(linux_ping_probe_test PRIVATE ois_linux)
    add_test(NAME linux_ping_probe_contract COMMAND linux_ping_probe_test)

    add_executable(service_probe_test tests/serviceprobe_test.cpp)
    target_link_libraries(service_probe_test PRIVATE ois_linux)
    add_test(NAME service_probe_contract COMMAND service_probe_test --skip-tls)
    add_test(NAME service_probe_tls_integration COMMAND service_probe_test)

    add_executable(hostname_resolver_test tests/hostnameresolver_test.cpp)
    target_link_libraries(hostname_resolver_test PRIVATE ois_linux)
    add_test(NAME hostname_resolver_contract COMMAND hostname_resolver_test)

    add_executable(scan_runners_test tests/scanrunners_test.cpp)
    target_link_libraries(scan_runners_test PRIVATE ois_runtime)
    add_test(NAME scan_runners_contract COMMAND scan_runners_test)

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
    add_test(NAME vendor_data_reproducibility
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tools/update_oui.py --offline --check)
    add_test(NAME vendor_data_generator_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/ouidata_test.py)
    add_test(NAME quality_gate_policy
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/qualitygatepolicy_test.py)
    add_test(NAME debian_dependency_portability
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/debiandependency_test.py)
    add_test(NAME supported_package_validation_policy
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/supportedpackage_test.py)
    add_test(NAME release_bundle_contract
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/releasebundle_test.py)
    add_test(NAME installed_metadata_contract
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/metadatacontract_test.py
                --build-dir ${CMAKE_BINARY_DIR}
                --app-id ${OIS_APP_ID}
                --version ${PROJECT_VERSION})

    add_test(NAME prefix_safety_contract
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/prefixsafety_test.py
                --build-dir ${CMAKE_BINARY_DIR}
                --app-id ${OIS_APP_ID})
    set_tests_properties(
        installed_metadata_contract prefix_safety_contract
        PROPERTIES RUN_SERIAL TRUE)

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

    add_executable(metadata_screenshot_tool
        EXCLUDE_FROM_ALL
        tests/metadatascreenshot.cpp resources/resources.qrc)
    target_link_libraries(metadata_screenshot_tool PRIVATE ois_ui)
endif()

set_target_properties(open_ip_scanner PROPERTIES
    OUTPUT_NAME "open-ip-scanner"
)
target_compile_definitions(open_ip_scanner PRIVATE
    OPEN_IP_SCANNER_APP_ID="${OIS_APP_ID}")

install(TARGETS open_ip_scanner
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
    "${OIS_GENERATED_RESOURCE_DIR}/${OIS_APP_ID}.desktop"
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/applications
)

install(FILES
    resources/app_icon.svg
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps
    RENAME ${OIS_APP_ID}.svg
)

install(FILES
    resources/app_icon.svg
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pixmaps
    RENAME ${OIS_APP_ID}.svg
)

install(FILES
    "${OIS_GENERATED_RESOURCE_DIR}/${OIS_APP_ID}.metainfo.xml"
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/metainfo
)

set(OIS_PACKAGE_DOC_DIR "${CMAKE_INSTALL_DATAROOTDIR}/doc/open-ip-scanner")
install(FILES
    packaging/debian/copyright
    "${OIS_GENERATED_RESOURCE_DIR}/changelog.gz"
    DESTINATION "${OIS_PACKAGE_DOC_DIR}"
)
install(FILES
    data/README.md
    DESTINATION "${OIS_PACKAGE_DOC_DIR}"
    RENAME vendor-data-sources.md
)
install(FILES
    docs/user-guide.md
    docs/support.md
    docs/data-provenance.md
    docs/security.md
    docs/known-limitations.md
    docs/release-checklist.md
    docs/platform-support.md
    DESTINATION "${OIS_PACKAGE_DOC_DIR}"
)
install(FILES
    "${OIS_GENERATED_RESOURCE_DIR}/open-ip-scanner.1.gz"
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
)

# Cleanup legacy integration filenames from older installs in this prefix.
install(CODE "
  file(REMOVE
    \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/applications/open_ip_scanner.desktop\"
    \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/applications/open-ip-scanner.desktop\"
    \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps/open_ip_scanner.svg\"
    \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps/open-ip-scanner.svg\"
    \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/pixmaps/open_ip_scanner.svg\"
    \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/pixmaps/open-ip-scanner.svg\"
    \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/metainfo/open-ip-scanner.metainfo.xml\")
")

# Record the effective installed paths together in one atomically replaced
# state manifest after all install and legacy-cleanup actions have succeeded.
install(SCRIPT "${CMAKE_BINARY_DIR}/write_uninstall_state.cmake")

set(CPACK_PACKAGE_NAME "open-ip-scanner")
set(CPACK_PACKAGE_VENDOR "Open IP Scanner")
set(CPACK_PACKAGE_CONTACT "Michael Beutler <mikebeutler84@gmail.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Linux x86-64 IPv4 network scanner using Qt 6.4+")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
    "Open IP Scanner discovers devices on authorized IPv4 networks and enriches
 results with interface-scoped neighbor, hostname, vendor, and bounded service
 evidence. It provides progressive results, cancellable accuracy profiles,
 CSV export, and privacy-preserving diagnostics in a Qt desktop interface.")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_DIRECTORY "${CMAKE_BINARY_DIR}/package-scratch")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE
    "https://github.com/calculatetech/open-ip-scanner")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "iputils-ping, iproute2")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "avahi-daemon")
set(CPACK_PROJECT_CONFIG_FILE
    "${CMAKE_SOURCE_DIR}/cmake/CPackProjectConfig.cmake")
set(CPACK_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
set(CPACK_STRIP_FILES "bin/open-ip-scanner")

include(CPack)

configure_file(
    ${CMAKE_SOURCE_DIR}/cmake_uninstall.cmake.in
    ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
    @ONLY
)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
)

add_custom_target(install-local
    COMMAND ${CMAKE_COMMAND}
            -DLOCAL_ACTION=install
            -DBUILD_DIR=${CMAKE_BINARY_DIR}
            -DUNINSTALL_SCRIPT=${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
            -DREFRESH_SCRIPT=${CMAKE_SOURCE_DIR}/cmake/refresh_desktop_caches.cmake
            -P ${CMAKE_SOURCE_DIR}/cmake/local_prefix_action.cmake
    VERBATIM
)

add_custom_target(uninstall-local
    COMMAND ${CMAKE_COMMAND}
            -DLOCAL_ACTION=uninstall
            -DBUILD_DIR=${CMAKE_BINARY_DIR}
            -DUNINSTALL_SCRIPT=${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
            -DREFRESH_SCRIPT=${CMAKE_SOURCE_DIR}/cmake/refresh_desktop_caches.cmake
            -P ${CMAKE_SOURCE_DIR}/cmake/local_prefix_action.cmake
    VERBATIM
)
