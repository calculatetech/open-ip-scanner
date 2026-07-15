include("${CMAKE_CURRENT_LIST_DIR}/PlatformSupport.cmake")

ois_validate_platform("${OIS_TEST_SYSTEM_NAME}"
                      "${OIS_TEST_SYSTEM_PROCESSOR}"
                      "${OIS_TEST_POINTER_SIZE}")
