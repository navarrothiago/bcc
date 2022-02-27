# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")


include_directories(${PROJECT_SOURCE_DIR}/src/cc)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/libbpf/include/uapi)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/api)

add_executable(c_test_perf_reader test_perf_reader.cc)
if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  target_link_libraries(c_test_perf_reader bcc-static)
else()
  target_link_libraries(c_test_perf_reader bcc-shared)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-result -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -frtti")

add_test(NAME c_test_perf_reader COMMAND c_test_perf_reader sudo ${CMAKE_CURRENT_BINARY_DIR}/c_test_perf_reader)
