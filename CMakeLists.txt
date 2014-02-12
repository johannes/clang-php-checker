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

#option(clangphpchecker_BUILD_STATIC
#  "Build clangphpchecker as a static library (in addition to a shared one)" OFF)

set(LLVM_EXPORTED_SYMBOL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/clangphpchecker.exports)

if(MSVC)
  set(LLVM_EXPORTED_SYMBOL_FILE)
endif()

if( LLVM_ENABLE_PIC )
  add_clang_library(clangphpchecker SHARED ${SOURCES})
  target_link_libraries(clangphpchecker ${LIBRARIES})
  #  add_dependencies(clangphpchecker ${GENERATED_HEADERS} clang-headers)

  if(WIN32)
    set_target_properties(libclang
      PROPERTIES
      OUTPUT_NAME "clangphpchecker"
      VERSION ${LIBCLANG_LIBRARY_VERSION}
      DEFINE_SYMBOL _CINDEX_LIB_)
  else()
    set_target_properties(libclang
      PROPERTIES
      OUTPUT_NAME "clangphpchecker"
      VERSION ${LIBCLANG_LIBRARY_VERSION}
      DEFINE_SYMBOL _CINDEX_LIB_)
  endif()

  if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(clangphpchecker_LINK_FLAGS " -Wl,-compatibility_version -Wl,1")
    if (DEFINED ${LLVM_SUBMIT_VERSION})
      set(clangphpchecker_LINK_FLAGS
        "${clangphpchecker_LINK_FLAGS} -Wl,-current_version -Wl,${LLVM_SUBMIT_VERSION}.${LLVM_SUBMIT_SUBVERSION}")
    endif()

    set_property(TARGET clangphpchecker APPEND_STRING PROPERTY
                 LINK_FLAGS ${clangphpchecker_LINK_FLAGS})
    set_target_properties(clangphpchecker
      PROPERTIES
      INSTALL_NAME_DIR "@rpath")
  endif()


  set(clangphpchecker_STATIC_TARGET_NAME clangphpchecker_static)
else()
  set(clangphpchecker_STATIC_TARGET_NAME clangphpchecker)
endif()

if( (NOT LLVM_ENABLE_PIC OR clangphpchecker_BUILD_STATIC) AND NOT WIN32 )
  add_clang_library(${clangphpchecker_STATIC_TARGET_NAME} STATIC ${SOURCES})
  target_link_libraries(${clangphpchecker_STATIC_TARGET_NAME} ${LIBRARIES})
  add_dependencies(${clangphpchecker_STATIC_TARGET_NAME} ${GENERATED_HEADERS} clang-headers)

  set_target_properties(${clangphpchecker_STATIC_TARGET_NAME}
    PROPERTIES
    OUTPUT_NAME "clangphpchecker")
endif()
