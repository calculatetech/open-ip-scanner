if(CPACK_GENERATOR STREQUAL "DEB")
    set(SHLIBDEPS_EXECUTABLE
        "${CMAKE_CURRENT_LIST_DIR}/../scripts/portable-dpkg-shlibdeps.py")
endif()
