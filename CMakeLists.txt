cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

project(clangPHPChecker CXX)

Find_Package(LLVM REQUIRED)
link_directories( ${LLVM_LIB_DIR} )

Find_Package(Clang REQUIRED)
include_directories( ${CLANG_INCLUDE_DIRS} )

add_definitions("-fno-rtti")
add_definitions("-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS ")

#target_link_libraries(clangPHPChecker ${CLANG_LIBS} ${LLVM_LIBS_CORE} )
if (WIN32)
	add_library(clangPHPChecker SHARED  PHPZPPChecker.cpp PHPChecker.def)
	target_link_libraries(clangPHPChecker ${CLANG_LIBS} LLVMSupport )
else()
	add_library(clangPHPChecker SHARED  PHPZPPChecker.cpp)
	target_link_libraries(clangPHPChecker)
endif()
