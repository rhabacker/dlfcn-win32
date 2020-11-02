set(headers dlfcn.h)
set(sources dlfcn.c)

if(BUILD_SHARED_LIBS)
    add_library(dl ${sources})
    target_compile_options(dl PRIVATE -DSHARED)
    # Correctly export the location of installed includes in the target
    target_include_directories(dl INTERFACE $<INSTALL_INTERFACE:include>)

    install (TARGETS dl EXPORT dlfcn-win32-targets
                        RUNTIME DESTINATION bin
                        LIBRARY DESTINATION lib${LIB_SUFFIX}
                        ARCHIVE DESTINATION lib${LIB_SUFFIX})
endif()
install (FILES ${headers} DESTINATION include)

if(ENABLE_STATIC)
    add_library(dl_static STATIC ${sources})
    set_target_properties(dl_static PROPERTIES OUTPUT_NAME dl)
    target_include_directories(dl_static INTERFACE $<INSTALL_INTERFACE:include>)

    install (TARGETS dl_static EXPORT dlfcn-win32-targets
                        RUNTIME DESTINATION bin
                        LIBRARY DESTINATION lib${LIB_SUFFIX}
                        ARCHIVE DESTINATION lib${LIB_SUFFIX})
endif()

# Export the targets  (build tree)
export(EXPORT dlfcn-win32-targets
       FILE "${CMAKE_BINARY_DIR}/dlfcn-win32-targets.cmake"
       NAMESPACE dlfcn-win32::
)

# Write the CMake config file
set(CMAKE_CONF_INSTALL_DIR share/dlfcn-win32)
set(INCLUDE_INSTALL_DIR include)
include(CMakePackageConfigHelpers)
configure_package_config_file(../dlfcn-win32-config.cmake.in ${CMAKE_BINARY_DIR}/dlfcn-win32-config.cmake
                              INSTALL_DESTINATION ${CMAKE_CONF_INSTALL_DIR}
                              PATH_VARS INCLUDE_INSTALL_DIR
                              NO_CHECK_REQUIRED_COMPONENTS_MACRO)

# Install the targets (install)
install(EXPORT dlfcn-win32-targets
        FILE dlfcn-win32-targets.cmake
        NAMESPACE dlfcn-win32::
        DESTINATION ${CMAKE_CONF_INSTALL_DIR})

# Install the CMake config file
install(FILES ${CMAKE_BINARY_DIR}/dlfcn-win32-config.cmake
        DESTINATION ${CMAKE_CONF_INSTALL_DIR})
