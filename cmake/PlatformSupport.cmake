function(ois_validate_platform system_name system_processor pointer_size)
    if(NOT system_name STREQUAL "Linux")
        message(FATAL_ERROR "Open IP Scanner 1.0 supports Linux only")
    endif()

    string(TOLOWER "${system_processor}" normalized_processor)
    if(NOT normalized_processor MATCHES "^(x86_64|amd64)$")
        message(FATAL_ERROR
            "Open IP Scanner 1.0 supports Linux x86-64 only; detected ${system_processor}")
    endif()

    if(NOT pointer_size EQUAL 8)
        message(FATAL_ERROR
            "Open IP Scanner 1.0 requires a 64-bit ABI; detected ${pointer_size}-byte pointers")
    endif()
endfunction()
