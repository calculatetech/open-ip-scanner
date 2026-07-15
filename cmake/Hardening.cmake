include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)
include(CheckPIESupported)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif()

check_pie_supported(LANGUAGES CXX OUTPUT_VARIABLE OIS_PIE_ERROR)
if(NOT CMAKE_CXX_LINK_PIE_SUPPORTED)
    message(FATAL_ERROR "Release PIE is unsupported: ${OIS_PIE_ERROR}")
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(OIS_RELEASE_COMPILE_FLAGS
    -fstack-protector-strong
    -fstack-clash-protection
    -fcf-protection=full)
foreach(flag IN LISTS OIS_RELEASE_COMPILE_FLAGS)
    string(MAKE_C_IDENTIFIER "OIS_SUPPORTS_${flag}" support_variable)
    check_cxx_compiler_flag("${flag}" "${support_variable}")
    if(NOT ${support_variable})
        message(FATAL_ERROR "Required Release hardening flag is unsupported: ${flag}")
    endif()
    add_compile_options("$<$<CONFIG:Release>:${flag}>")
endforeach()

# Clear any toolchain default before selecting the audited fortification level.
add_compile_options(
    "$<$<CONFIG:Release>:-U_FORTIFY_SOURCE>"
    "$<$<CONFIG:Release>:-D_FORTIFY_SOURCE=3>")

set(OIS_RELEASE_LINK_FLAGS "-Wl,-z,relro,-z,now")
check_linker_flag(CXX "${OIS_RELEASE_LINK_FLAGS}" OIS_SUPPORTS_RELRO_NOW)
if(NOT OIS_SUPPORTS_RELRO_NOW)
    message(FATAL_ERROR
        "Required Release RELRO/immediate-binding flags are unsupported")
endif()
add_link_options("$<$<CONFIG:Release>:${OIS_RELEASE_LINK_FLAGS}>")
