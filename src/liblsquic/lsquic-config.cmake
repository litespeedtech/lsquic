@PACKAGE_INIT@

set_and_check(lsquic_INCLUDE_DIR "@PACKAGE_CMAKE_INSTALL_INCLUDEDIR@")
include("${CMAKE_CURRENT_LIST_DIR}/lsquic-targets.cmake")
