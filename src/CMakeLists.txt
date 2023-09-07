file(GLOB LIB_SOURCES "*.cc")

add_library(csc458_debug STATIC ${LIB_SOURCES})

add_library(csc458_sanitized EXCLUDE_FROM_ALL STATIC ${LIB_SOURCES})
target_compile_options(csc458_sanitized PUBLIC ${SANITIZING_FLAGS})

add_library(csc458_optimized EXCLUDE_FROM_ALL STATIC ${LIB_SOURCES})
target_compile_options(csc458_optimized PUBLIC "-O2")

macro(add_app exec_name)
  add_executable("${exec_name}" "${exec_name}.cc")
  target_link_libraries("${exec_name}" csc458_debug)
  target_link_libraries("${exec_name}" util_debug)
endmacro(add_app)

add_app(webget)
