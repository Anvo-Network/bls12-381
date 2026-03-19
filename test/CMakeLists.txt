add_executable(unittests unittests.cpp)
target_link_libraries(unittests bls12-381)

add_executable(adversarial_tests adversarial_tests.cpp)
target_link_libraries(adversarial_tests bls12-381)

add_test(NAME bls12-381 COMMAND unittests)
add_test(NAME bls12-381-adversarial COMMAND adversarial_tests)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  add_test(NAME bls12-381-nobmi2 COMMAND unittests)
  set_tests_properties(bls12-381-nobmi2 PROPERTIES ENVIRONMENT "BLS_DISABLE_BMI2=1")
endif()