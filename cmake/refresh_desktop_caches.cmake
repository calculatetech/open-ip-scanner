if(NOT DEFINED REFRESH_PREFIX OR REFRESH_PREFIX STREQUAL "")
  message(FATAL_ERROR "REFRESH_PREFIX is required")
endif()
if(NOT IS_ABSOLUTE "${REFRESH_PREFIX}")
  message(FATAL_ERROR "REFRESH_PREFIX must be an absolute path")
endif()
if("${REFRESH_PREFIX}" MATCHES "[;\n\r]")
  message(FATAL_ERROR "REFRESH_PREFIX contains unsupported characters")
endif()
cmake_path(SET _refresh_prefix NORMALIZE "${REFRESH_PREFIX}")

if(DEFINED OIS_TEST_EFFECTIVE_UID)
  set(_effective_uid "${OIS_TEST_EFFECTIVE_UID}")
else()
  execute_process(
    COMMAND id -u
    OUTPUT_VARIABLE _effective_uid
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _id_result)
  if(NOT _id_result EQUAL 0)
    message(WARNING "Could not determine user identity; desktop caches were not refreshed")
    return()
  endif()
endif()

if(_effective_uid STREQUAL "0")
  message(STATUS "Skipping user-session desktop cache refresh while running as root")
  return()
endif()

function(ois_run_cache_tool program)
  execute_process(COMMAND "${program}" ${ARGN} RESULT_VARIABLE _tool_result)
  if(NOT _tool_result EQUAL 0)
    message(WARNING "Desktop cache refresh command failed: ${program}")
  endif()
endfunction()

set(_applications_dir "${_refresh_prefix}/share/applications")
find_program(UPDATE_DESKTOP_DATABASE update-desktop-database)
if(UPDATE_DESKTOP_DATABASE AND EXISTS "${_applications_dir}")
  ois_run_cache_tool("${UPDATE_DESKTOP_DATABASE}" "${_applications_dir}")
endif()

set(_icon_dir "${_refresh_prefix}/share/icons/hicolor")
find_program(GTK_UPDATE_ICON_CACHE gtk-update-icon-cache)
if(GTK_UPDATE_ICON_CACHE AND EXISTS "${_icon_dir}")
  ois_run_cache_tool("${GTK_UPDATE_ICON_CACHE}" -f -t "${_icon_dir}")
endif()

find_program(KBUILDSYCOCA6 kbuildsycoca6)
if(KBUILDSYCOCA6)
  ois_run_cache_tool("${KBUILDSYCOCA6}" --noincremental)
endif()
