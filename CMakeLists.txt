set(LLVM_LINK_COMPONENTS
  Support
  )

set(SOURCES
  PHPZPPChecker.cpp
  )

set(LIBRARIES
  clangAST
  clangAnalysis
  clangBasic
  clangLex
  clangStaticAnalyzerCore
  )

#option(clangPHPChecker_BUILD_STATIC
#  "Build clangPHPChecker as a static library (in addition to a shared one)" OFF)

#set(LLVM_EXPORTED_SYMBOL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/clangPHPChecker.exports)

#if(MSVC)
#  set(LLVM_EXPORTED_SYMBOL_FILE)
#endif()

if( LLVM_ENABLE_PIC )
  add_clang_library(clangPHPChecker SHARED ${SOURCES})
  target_link_libraries(clangPHPChecker ${LIBRARIES})
  #  add_dependencies(clangPHPChecker ${GENERATED_HEADERS} clang-headers)

  if(WIN32)
    set_target_properties(libclang
      PROPERTIES
      OUTPUT_NAME "clangPHPChecker"
      VERSION ${LIBCLANG_LIBRARY_VERSION}
      DEFINE_SYMBOL _CINDEX_LIB_)
  else()
    set_target_properties(libclang
      PROPERTIES
      OUTPUT_NAME "clangPHPChecker"
      VERSION ${LIBCLANG_LIBRARY_VERSION}
      DEFINE_SYMBOL _CINDEX_LIB_)
  endif()

  if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(clangPHPChecker_LINK_FLAGS " -Wl,-compatibility_version -Wl,1")
    if (DEFINED ${LLVM_SUBMIT_VERSION})
      set(clangPHPChecker_LINK_FLAGS
        "${clangPHPChecker_LINK_FLAGS} -Wl,-current_version -Wl,${LLVM_SUBMIT_VERSION}.${LLVM_SUBMIT_SUBVERSION}")
    endif()

    set_property(TARGET clangPHPChecker APPEND_STRING PROPERTY
                 LINK_FLAGS ${clangPHPChecker_LINK_FLAGS})
    set_target_properties(clangPHPChecker
      PROPERTIES
      INSTALL_NAME_DIR "@rpath")
  endif()


  set(clangPHPChecker_STATIC_TARGET_NAME clangPHPChecker_static)
else()
  set(clangPHPChecker_STATIC_TARGET_NAME clangPHPChecker)
endif()

if( (NOT LLVM_ENABLE_PIC OR clangPHPChecker_BUILD_STATIC) AND NOT WIN32 )
  add_clang_library(${clangPHPChecker_STATIC_TARGET_NAME} STATIC ${SOURCES})
  target_link_libraries(${clangPHPChecker_STATIC_TARGET_NAME} ${LIBRARIES})
  add_dependencies(${clangPHPChecker_STATIC_TARGET_NAME} ${GENERATED_HEADERS} clang-headers)

  set_target_properties(${clangPHPChecker_STATIC_TARGET_NAME}
    PROPERTIES
    OUTPUT_NAME "clangPHPChecker")
endif()
