//===-- PHPZPPCheckerImpl.cpp ---------------------------------------------===//
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

typedef llvm::Optional<const std::string> PHPNativeType;
typedef std::multimap<char, const PHPNativeType> PHPTypeMap;
typedef std::pair<const PHPTypeMap::const_iterator, const PHPTypeMap::const_iterator> PHPTypeRange;

#define BEGIN_MAP(versionname)                                                 \
  struct versionname;                                                          \
  template <> const PHPTypeMap getMap<versionname>() {                         \
    PHPTypeMap retval;

#define MAPPING(format, type)                                                  \
  retval.insert(std::pair<char, const PHPNativeType>((format), std::string(type)))
#define MAPPING_EMPTY(format)                                                  \
  retval.insert(std::pair<char, const PHPNativeType>((format), PHPNativeType()));
#define END_MAPPING()                                                          \
  return retval;                                                               \
  }

namespace {
template <typename T> const PHPTypeMap getMap() {}

// These mappings map a zpp modifier to underlying types. Mind that we
// reference the canonical form here, thus HashTable becomes struct _hashtable.
// Also mind the indirection level: zpp receives the address of the object to
// store in wich adds a level.
// Some types return multiple values, these are added multiple times inorder to
// this list (i.e. a string "s" consists of a char array and length)
// The identifier (i.e. PHP55) has to ve a valid C++ identifier as we declare a
// struct using it and use it as template parameter type.
BEGIN_MAP(PHP55) {
  MAPPING('a', "struct _zval_struct **");
  MAPPING('A', "struct _zval_struct **");
  MAPPING('b', "unsigned char *");
  MAPPING('C', "struct _zend_class_entry **");
  MAPPING('d', "double *");
  MAPPING('f', "struct _zend_fcall_info *");
  MAPPING('f', "struct _zend_fcall_info_cache *");
  MAPPING('h', "struct _hashtable **");
  MAPPING('H', "struct _hashtable **");
  MAPPING('l', "long *");
  MAPPING('L', "long *");
  MAPPING('o', "struct _zend_class_entry **");
  MAPPING('O', "struct _zend_class_entry **");
  MAPPING('O', "struct _zend_class_entry *");
  MAPPING('p', "char **");
  MAPPING('p', "int *");
  MAPPING('r', "struct _zval_struct **");
  MAPPING('s', "char **");
  MAPPING('s', "int *");
  MAPPING('z', "struct _zval_struct **");
  MAPPING('Z', "struct _zval_struct ***");
  MAPPING_EMPTY('|');
  MAPPING_EMPTY('/');
  MAPPING_EMPTY('!')
  MAPPING('+', "struct _zval_struct ****");
  MAPPING('+', "int *");
  MAPPING('*', "struct _zval_struct ****");
  MAPPING('*', "int *");
}
END_MAPPING()

// TODO: This is a sample, please replace it if you add support for a new
// PHP version
BEGIN_MAP(PHPSample) {
  MAPPING('a', "struct _zval_struct **");
  MAPPING('A', "struct _zval_struct **");
}
END_MAPPING()


class PHPZPPCheckerImpl {
  mutable IdentifierInfo *IIzpp, *IIzpp_ex, *IIzpmp, *IIzpmp_ex;

  OwningPtr<BugType> InvalidTypeBugType;
  OwningPtr<BugType> InvalidModifierBugType;
  OwningPtr<BugType> WrongArgumentNumberBugType;

  mutable bool TSRMBuild;

  const PHPTypeMap map;

  void initIdentifierInfo(ASTContext &Ctx) const;

  const StringLiteral *getCStringLiteral(const SVal val) const;
  const QualType getTypeForSVal(const SVal val) const;
  bool compareTypeWithSVal(const SVal val, const std::string &expectedType,
                           CheckerContext &C) const;

public:
  PHPZPPCheckerImpl(const PHPTypeMap map);

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

// This template is kept minimal on purpose. The goal is to inject the modifier
// map into the actual implementation. Long term goal is to automatially detect
// the PHP version we are runnig with ut apparently checkers currently have no
// access to the preprocessor so we can't read PHP_VERSION_ID and would have to
// guess based on excistence of functions or similar. Medium term goal might be
// to add a checker-specific command line argument to pass the PHP version 
// instead of registering different checkers. This might be useful once we have
// different checkers.
template <typename Version>
class PHPZPPChecker : public Checker<check::PreCall> {
  const PHPZPPCheckerImpl impl;

public:
  PHPZPPChecker() : impl(getMap<Version>()) {}
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    impl.checkPreCall(Call, C);
  }
};

}



PHPZPPCheckerImpl::PHPZPPCheckerImpl(const PHPTypeMap map)
    : IIzpp(0), IIzpp_ex(0), IIzpmp(0), IIzpmp_ex(0), TSRMBuild(false),
      map(map) {
  InvalidTypeBugType.reset(new BugType("Invalid type", "PHP ZPP API Error"));

  InvalidModifierBugType.reset(
      new BugType("Invalid modifier", "PHP ZPP API Error"));

  WrongArgumentNumberBugType.reset(
      new BugType("Wrong number of zpp arguments", "PHP ZPP API Error"));
}

const StringLiteral *PHPZPPCheckerImpl::getCStringLiteral(const SVal val) const {

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

const QualType PHPZPPCheckerImpl::getTypeForSVal(const SVal val) const {
  const TypedValueRegion *TR =
      dyn_cast_or_null<TypedValueRegion>(val.getAsRegion());
  return TR->getLocationType().getCanonicalType();
}

bool PHPZPPCheckerImpl::compareTypeWithSVal(const SVal val,
                                            const std::string &expectedType,
                                            CheckerContext &C) const {
  if (expectedType != getTypeForSVal(val).getAsString()) {
    BugReport *R = new BugReport(
        *InvalidTypeBugType,
        std::string("Arguments don't match the type expected by the format "
                    "string (") +
            expectedType + std::string(" != ") +
            getTypeForSVal(val).getAsString() + std::string(")"),
        C.addTransition());
    R->markInteresting(val);
    C.emitReport(R);
    return false;
  }
  return true;
}

void PHPZPPCheckerImpl::checkPreCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  initIdentifierInfo(C.getASTContext());

  unsigned offset;

  if (!Call.isGlobalCFunction())
    return;

  const IdentifierInfo *callee = Call.getCalleeIdentifier();
  if (callee == IIzpp) {
    offset = 1;
  } else if (callee == IIzpp_ex) {
    offset = 2;
  } else if (callee == IIzpmp) {
    offset = 2;
  } else if (callee == IIzpmp_ex) {
    offset = 3;
  } else {
    return;
  }

  if (TSRMBuild) {
    ++offset;
  }

  const unsigned numArgs = Call.getNumArgs();
  if (numArgs <= offset)
    // Something is really weird - this should be caught by the compiler
    return;

  const StringLiteral *format_spec_sl =
      getCStringLiteral(Call.getArgSVal(offset));
  if (!format_spec_sl) {
    // TODO need a good way to report this, even though this is no error
    std::cout << "Couldn't get format string looked at offset " << offset << std::endl;
    Call.dump();
    return;
  }
  const StringRef format_spec = format_spec_sl->getBytes();

  // Call.dump();
  for (StringRef::const_iterator modifier = format_spec.begin(),
                                 last_mod = format_spec.end();
       modifier != last_mod; ++modifier) {
//std::cout << "  I am checking for " << *modifier << std::endl;
    const PHPTypeRange range = map.equal_range(*modifier);

    if (range.first == range.second) {
      BugReport *R = new BugReport(
          *InvalidModifierBugType,
          std::string("Unknown modifier '") + *modifier + "'", C.addTransition());
      C.emitReport(R);
      return;
    }

    for (PHPTypeMap::const_iterator type = range.first; type != range.second;
         ++type) {
      if (!type->second) {
        // Current modifier doesn't need an argument, these are special things
        // like |, ! or /
        continue;
      }
      ++offset;
//std::cout << "    I need a " << *type->second << " (" << offset << ")" << std::endl;
      if (numArgs <= offset) {
        BugReport *R = new BugReport(*WrongArgumentNumberBugType,
                                     "Too few arguments for format specified",
                                     C.addTransition());
        C.emitReport(R);
//std::cout << "!!!!I am missing args! " << numArgs << "<=" << offset << std::endl;
        return;
      }

      SVal val = Call.getArgSVal(offset);
      if (!compareTypeWithSVal(val, *type->second, C)) {
        // TODO: Move error reporting here?

        // Even if there is a type mismatch we can continue, most of the time
        // this should be a simple mistake by the user, in rare cases the user
        // missed an argument and will get many subsequent errors
      }
    }
  }

  if (numArgs > 1 + offset) {
    BugReport *R = new BugReport(*WrongArgumentNumberBugType,
                                 "Too many arguments for format specified",
                                 C.addTransition());
    R->markInteresting(Call.getArgSVal(offset));
    C.emitReport(R);
  }
}

void PHPZPPCheckerImpl::initIdentifierInfo(ASTContext &Ctx) const {
  if (IIzpp)
    return;

  IIzpp = &Ctx.Idents.get("zend_parse_parameters");
  IIzpp_ex = &Ctx.Idents.get("zend_parse_parameters_ex");
  IIzpmp = &Ctx.Idents.get("zend_parse_method_parameters");
  IIzpmp_ex = &Ctx.Idents.get("zend_parse_method_parameters_ex");

  IdentifierInfo *tsrm = &Ctx.Idents.get("ZTS");
  TSRMBuild = tsrm->hasMacroDefinition();
}




extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<PHPZPPChecker<PHP55> >(
      "php.ZPPChecker55",
      "Check zend_parse_parameter usage for PHP 5.3 - 5.5");
  registry.addChecker<PHPZPPChecker<PHPSample> >(
      "php.ZPPCheckerSample",
      "This is a sample, to be replaced with size_t version");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
