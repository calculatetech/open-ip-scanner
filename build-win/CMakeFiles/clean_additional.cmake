# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Release")
  file(REMOVE_RECURSE
  "CMakeFiles/open_ip_scanner_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/open_ip_scanner_autogen.dir/ParseCache.txt"
  "open_ip_scanner_autogen"
  )
endif()
