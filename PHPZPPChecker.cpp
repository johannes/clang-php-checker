//===-- PHPZPPChecker.cpp -----------------------------------------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Defines a checker for proper use of PHP's zend_parse_parameters(),
// zend_parse_parameters(), zend_parse_method_parameters() and
// zend_parse_method_parameters_ex() functions.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include <iostream>

using namespace clang;
using namespace ento;

namespace {
class PHPZPPChecker : public Checker<check::PreCall> {
  mutable IdentifierInfo *IIzpp, *IIzpp_ex, *IIzpmp, *IIzpmp_ex;

  OwningPtr<BugType> InvalidTypeBugType;
  OwningPtr<BugType> WrongArgumentNumberBugType;

  mutable bool TSRMBuild;

  void initIdentifierInfo(ASTContext &Ctx) const;

  const StringLiteral *getCStringLiteral(CheckerContext &C, SVal val) const;
  const QualType getTypeForSVal(SVal val) const;
  void compareTypeWithSVal(SVal val, const std::string &expectedType) const;
  void check(SVal val, char modifier) const;
public:
  PHPZPPChecker();

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace
/*
ArgValidator::~ArgValidator() {


}
*/
const QualType PHPZPPChecker::getTypeForSVal(SVal val) const {
  const TypedValueRegion *TR = dyn_cast_or_null<TypedValueRegion>(
      val.getAsRegion());
  return TR->getLocationType().getCanonicalType();
}

void PHPZPPChecker::compareTypeWithSVal(SVal val, const std::string &expectedType) const {
/*

*/
  if (expectedType != getTypeForSVal(val).getAsString()) {
    // std::cout << std::endl << expectedType << " != " <<
    // getTypeForNextArg().getAsString() << std::endl;
/*
    BugReport *R = new BugReport(
        InvalidTypeBugType,
        std::string("Arguments don't match the type expected by the format "
                    "string (") +
            expectedType + std::string(" != ") +
            getTypeForSVal(val).getAsString() + std::string(")"),
        C.addTransition());
    R->markInteresting(val));
    C.emitReport(R);
*/
  }
}

void PHPZPPChecker::check(SVal val, char modifier) const {
  switch (modifier) {
  case 'a':
  case 'A':
    compareTypeWithSVal(val, "struct _zval_struct **");
    break;
  case 'b':
    compareTypeWithSVal(val, "unsigned char *");
    break;
  case 'C':
    compareTypeWithSVal(val, "struct _zend_class_entry **");
    break;
  case 'd':
    compareTypeWithSVal(val, "double *");
    break;
  case 'f':
    compareTypeWithSVal(val, "struct _zend_fcall_info *");
    compareTypeWithSVal(val, "struct _zend_fcall_info_cache *"); ///// TODO
    break;
  case 'h':
  case 'H':
    compareTypeWithSVal(val, "struct _hashtable **");
    break;
  case 'l':
  case 'L':
    compareTypeWithSVal(val, "long *");
    break;
  case 'o':
    compareTypeWithSVal(val, "struct _zend_class_entry **");
    break;
  case 'O':
    compareTypeWithSVal(val, "struct _zend_class_entry **");
    compareTypeWithSVal(val, "struct _zend_class_entry *"); ///////// TODO
    break;
  case 'p':
    compareTypeWithSVal(val, "char **");
    compareTypeWithSVal(val, "int *"); ///////// TODO
    break;
  case 'r':
    compareTypeWithSVal(val, "struct _zval_struct **");
    break;
  case 's':
    compareTypeWithSVal(val, "char **");
    compareTypeWithSVal(val, "int *");   /////////// TODO
    break;
  case 'z':
    compareTypeWithSVal(val, "struct _zval_struct **");
    break;
  case 'Z':
    compareTypeWithSVal(val, "struct _zval_struct ***");
    break;
  case '|':
  case '/':
  case '!':
    break;
  case '+':
  case '*':
    compareTypeWithSVal(val, "struct _zval_struct ****");
    compareTypeWithSVal(val, "int *");   ////// TODO
  default:
    break;
    // error
  }
}

PHPZPPChecker::PHPZPPChecker()
    : IIzpp(0), IIzpp_ex(0), IIzpmp(0), IIzpmp_ex(0), TSRMBuild(false) {
  InvalidTypeBugType.reset(new BugType("Invalid type", "PHP ZPP API Error"));

  WrongArgumentNumberBugType.reset(
      new BugType("Wrong number of zpp arguments", "PHP ZPP API Error"));
}

const StringLiteral *PHPZPPChecker::getCStringLiteral(CheckerContext &C,
                                                      SVal val) const {

  // Copied from tools/clang/lib/StaticAnalyzer/Checkers/CStringChecker.cpp

  // Get the memory region pointed to by the val.
  const MemRegion *bufRegion = val.getAsRegion();
  if (!bufRegion)
    return NULL;

  // Strip casts off the memory region.
  bufRegion = bufRegion->StripCasts();

  // Cast the memory region to a string region.
  const StringRegion *strRegion = dyn_cast<StringRegion>(bufRegion);
  if (!strRegion)
    return NULL;

  // Return the actual string in the string region.
  return strRegion->getStringLiteral();
}

void PHPZPPChecker::checkPreCall(const CallEvent &Call,
                                 CheckerContext &C) const {
  initIdentifierInfo(C.getASTContext());

  unsigned offset;

  if (!Call.isGlobalCFunction())
    return;

  if (Call.getCalleeIdentifier() == IIzpp) {
    offset = 1;
  } else if (Call.getCalleeIdentifier() == IIzpp_ex) {
    offset = 2;
  } else if (Call.getCalleeIdentifier() == IIzpmp) {
    offset = 2;
  } else if (Call.getCalleeIdentifier() == IIzpmp_ex) {
    offset = 3;
  } else {
    return;
  }

  if (TSRMBuild) {
    ++offset;
  }

  if (Call.getNumArgs() <= offset)
    // Something is really weird - this should be caught by the compiler
    return;

  const StringLiteral *format_spec_sl =
      getCStringLiteral(C, Call.getArgSVal(offset));
  if (!format_spec_sl) {
    // TODO need a good way to report this, even though this is no error
    std::cout << "Couldn't get format string\n";
    return;
  }
  StringRef format_spec = format_spec_sl->getBytes();

  for (StringRef::const_iterator it = format_spec.begin();
       it != format_spec.end(); ++it) {
    if (Call.getNumArgs() <= ++offset) {
      BugReport *R = new BugReport(WrongArgumentNumberBugType,
                                   "Too few arguments for format specified",
                                   C.addTransition());
      C.emitReport(R);
    }

    return;
  }
    check(Call.getArgSVal(offset), *it);
  }

  if (Call.getNumArgs() > 1 + offset) {
    BugReport *R = new BugReport(WrongArgumentNumberBugType,
                                 "Too many arguments for format specified",
                                 C.addTransition());
    R->markInteresting(Call.getArgSVal(offset + 1));
    C.emitReport(R);
  }
}

void PHPZPPChecker::initIdentifierInfo(ASTContext &Ctx) const {
  if (IIzpp)
    return;

  IIzpp = &Ctx.Idents.get("zend_parse_parameters");
  IIzpp_ex = &Ctx.Idents.get("zend_parse_parameters_ex");
  IIzpmp = &Ctx.Idents.get("zend_parse_method_parameters");
  IIzpmp_ex = &Ctx.Idents.get("zend_parse_method_parameters_ex");

  IdentifierInfo *tsrm = &Ctx.Idents.get("TSRMLS_CC");
  TSRMBuild = tsrm->hasMacroDefinition();
}

extern "C"
void clang_registerCheckers (CheckerRegistry &registry) {
  registry.addChecker<PHPZPPChecker>("php.PHPZPPChecker55", "Check zend_parse_parameter usage for PHP 5.3 - 5.5");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;

