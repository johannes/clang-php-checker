set(MODULE TRUE)

set( LLVM_LINK_COMPONENTS support mc)

add_clang_library(PHPChecker PHPZPPChecker.cpp)

add_dependencies(PHPChecker
  ClangAttrClasses
  ClangAttrList
  ClangCommentNodes
  ClangDeclNodes
  ClangDiagnosticCommon
  ClangStmtNodes
  )

target_link_libraries(PHPChecker
  clangStaticAnalyzerCore
  )

set_target_properties(PHPChecker
  PROPERTIES
  LINKER_LANGUAGE CXX
  PREFIX "")
