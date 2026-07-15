foreach(_required_variable IN ITEMS LOCAL_ACTION BUILD_DIR UNINSTALL_SCRIPT REFRESH_SCRIPT)
  if(NOT DEFINED ${_required_variable} OR "${${_required_variable}}" STREQUAL "")
    message(FATAL_ERROR "${_required_variable} is required")
  endif()
endforeach()

if(NOT DEFINED ENV{HOME} OR "$ENV{HOME}" STREQUAL "" OR NOT IS_ABSOLUTE "$ENV{HOME}")
  message(FATAL_ERROR "HOME must be an absolute path for local install operations")
endif()
if("$ENV{HOME}" MATCHES "[;\n\r]")
  message(FATAL_ERROR "HOME contains unsupported characters for local install operations")
endif()
cmake_path(SET _local_prefix NORMALIZE "$ENV{HOME}/.local")

if(LOCAL_ACTION STREQUAL "install")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${_local_prefix}"
    RESULT_VARIABLE _action_result)
elseif(LOCAL_ACTION STREQUAL "uninstall")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" "-DUNINSTALL_PREFIX=${_local_prefix}"
            -P "${UNINSTALL_SCRIPT}"
    RESULT_VARIABLE _action_result)
else()
  message(FATAL_ERROR "Unknown LOCAL_ACTION: ${LOCAL_ACTION}")
endif()

if(NOT _action_result EQUAL 0)
  message(FATAL_ERROR "Local ${LOCAL_ACTION} failed")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" "-DREFRESH_PREFIX=${_local_prefix}"
          -P "${REFRESH_SCRIPT}"
  RESULT_VARIABLE _refresh_result)
if(NOT _refresh_result EQUAL 0)
  message(FATAL_ERROR "Local desktop cache refresh failed")
endif()
