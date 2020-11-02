include_directories(../src)

add_library(testdll SHARED testdll.c)
set_target_properties(testdll PROPERTIES PREFIX "")
if(ENABLE_STATIC)
    add_custom_command(
        TARGET testdll
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:testdll> $<TARGET_FILE_DIR:testdll>/static/$<TARGET_FILE_NAME:testdll>
        COMMENT "copying testdll for static test"
    )
endif()

add_library(testdll3 SHARED testdll3.c)
set_target_properties(testdll3 PROPERTIES PREFIX "")
if(ENABLE_STATIC)
    add_custom_command(
        TARGET testdll3
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:testdll3> $<TARGET_FILE_DIR:testdll3>/static/$<TARGET_FILE_NAME:testdll3>
        COMMENT "copying testdll3 for static test"
    )
endif()

if(BUILD_SHARED_LIBS)
    add_library(testdll2 SHARED testdll2.c)
    set_target_properties(testdll2 PROPERTIES PREFIX "")
    target_link_libraries(testdll2 dl)

    add_executable(t_dlfcn test.c)
    target_link_libraries(t_dlfcn dl)
    add_test(NAME t_dlfcn COMMAND ${WRAPPER} $<TARGET_FILE:t_dlfcn> WORKING_DIRECTORY $<TARGET_FILE_DIR:t_dlfcn>)
endif()

if(ENABLE_STATIC)
    add_library(testdll2_static SHARED testdll2.c)
    set_target_properties(testdll2_static PROPERTIES PREFIX "")
    set_target_properties(testdll2_static PROPERTIES OUTPUT_NAME testdll2)
    target_link_libraries(testdll2_static dl_static)
    set_target_properties(testdll2_static PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/static)

    add_executable(t_dlfcn_static test.c)
    target_link_libraries(t_dlfcn_static dl_static)
    target_compile_options(t_dlfcn_static PRIVATE -static)
    set_target_properties(t_dlfcn_static PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/static)
    add_test(NAME t_dlfcn_static COMMAND ${WRAPPER} $<TARGET_FILE:t_dlfcn_static> WORKING_DIRECTORY $<TARGET_FILE_DIR:t_dlfcn_static>)
endif()
