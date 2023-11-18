add_library(csc458_testing_debug STATIC common.cc)

add_library(csc458_testing_sanitized EXCLUDE_FROM_ALL STATIC common.cc)
target_compile_options(csc458_testing_sanitized PUBLIC ${SANITIZING_FLAGS})

add_custom_target(functionality_testing)

macro(add_test_exec exec_name)
  add_executable("${exec_name}_sanitized" EXCLUDE_FROM_ALL "${exec_name}.cc")
  target_compile_options("${exec_name}_sanitized" PUBLIC ${SANITIZING_FLAGS})
  target_link_options("${exec_name}_sanitized" PUBLIC ${SANITIZING_FLAGS})
  target_link_libraries("${exec_name}_sanitized" csc458_testing_sanitized)
  target_link_libraries("${exec_name}_sanitized" csc458_sanitized)
  target_link_libraries("${exec_name}_sanitized" util_sanitized)
  add_dependencies(functionality_testing "${exec_name}_sanitized")

  add_executable("${exec_name}" EXCLUDE_FROM_ALL "${exec_name}.cc")
  target_link_libraries("${exec_name}" csc458_testing_debug)
  target_link_libraries("${exec_name}" csc458_debug)
  target_link_libraries("${exec_name}" util_debug)
  add_dependencies(functionality_testing "${exec_name}")
endmacro(add_test_exec)

add_test_exec(net_interface_test_typical)
add_test_exec(net_interface_test_reply)
add_test_exec(net_interface_test_learn)
add_test_exec(net_interface_test_pending)
add_test_exec(net_interface_test_expiry)
add_test_exec(net_interface_test_independence)

add_test_exec(router_2hosts_1)
add_test_exec(router_2hosts_2)
add_test_exec(router_internet)
add_test_exec(router_hs_network)
add_test_exec(router_same_network)
add_test_exec(router_ttl)

