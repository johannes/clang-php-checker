//===-- PHPZPPChecker.cpp -------------------------------------------------===//
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

#define MAPPING(format, type)                                                  \
  map.insert(std::pair<char, const PHPNativeType>((format), std::string(type)))
#define MAPPING_EMPTY(format)                                                  \
  map.insert(std::pair<char, const PHPNativeType>((format), PHPNativeType()));

namespace {
// These mappings map a zpp modifier to underlying types. Mind that we
// reference the canonical form here, thus HashTable becomes struct _hashtable.
// Also mind the indirection level: zpp receives the address of the object to
// store in wich adds a level.
// Some types return multiple values, these are added multiple times inorder to
// this list (i.e. a string "s" consists of a char array and length)
// The identifier (i.e. PHP55) has to ve a valid C++ identifier as we declare a
// function using it.
static void fillMapPHP55(PHPTypeMap &map) {
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
  MAPPING('O', "struct _zval_struct **");
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

// TODO: This is a sample, please replace it if you add support for a new
// PHP version
static void fillMapPHPSample(PHPTypeMap &map) {
  MAPPING('a', "struct _zval_struct **");
  MAPPING('A', "struct _zval_struct **");
}

class PHPZPPChecker : public Checker<check::PreCall> {
  mutable IdentifierInfo *IIzpp, *IIzpp_ex, *IIzpmp, *IIzpmp_ex;

  OwningPtr<BugType> InvalidTypeBugType;
  OwningPtr<BugType> InvalidModifierBugType;
  OwningPtr<BugType> WrongArgumentNumberBugType;

  PHPTypeMap map;

  void initIdentifierInfo(ASTContext &Ctx) const;

  const StringLiteral *getCStringLiteral(const SVal val) const;
  bool compareTypeWithSVal(unsigned offset, char modifier, const SVal val, const std::string &expectedType,
                           CheckerContext &C) const;
  bool checkArgs(const StringRef &format_spec, unsigned &offset,
                 const unsigned numArgs, const CallEvent &Call,
                 CheckerContext &C) const;

public:
  PHPZPPChecker();

  typedef void (*MapFiller)(PHPTypeMap &);
  void setMap(MapFiller filler);
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

}

PHPZPPChecker::PHPZPPChecker()
    : IIzpp(0), IIzpp_ex(0), IIzpmp(0), IIzpmp_ex(0) {
  InvalidTypeBugType.reset(new BugType("Invalid type", "PHP ZPP API Error"));

  InvalidModifierBugType.reset(
      new BugType("Invalid modifier", "PHP ZPP API Error"));

  WrongArgumentNumberBugType.reset(
      new BugType("Wrong number of zpp arguments", "PHP ZPP API Error"));
}

void PHPZPPChecker::setMap(MapFiller filler) {
  map.clear();
  filler(map);
}

const StringLiteral *PHPZPPChecker::getCStringLiteral(const SVal val) const {

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

static const QualType getQualTypeForSVal(const SVal &val) {
  const MemRegion *region = val.getAsRegion();
  if (!region) {
    // TODO: pdo_dbh.c uses zpp(0 TSRMLS_CC, "z|z", NULL, NULL) to report an error
    // Should we report an error for such a construct? In other situations it could be wrong
    // For this specific case we could mitigate by checking whether the first argument (ht)
    // is 0 as it is hard coded in this case. Right now we report no error if NULL is passed.
    return QualType();
  }
  if (isa<TypedValueRegion>(region)) {
    return cast<TypedValueRegion>(region)->getLocationType().getCanonicalType();
  }
  if (isa<SymbolicRegion>(region)) {
    return cast<SymbolicRegion>(region)
        ->getSymbol()
        ->getType()
        .getCanonicalType();
  }
  return QualType();
}

bool PHPZPPChecker::compareTypeWithSVal(unsigned offset, char modifier, const SVal val,
                                            const std::string &expectedType,
                                            CheckerContext &C) const {
  const QualType type = getQualTypeForSVal(val);

  if (type.isNull()) {
    // TODO need a good way to report this, even though this is no error
    std::cout << "Couldn't get type for argument at offset " << offset << std::endl;
    val.dump();
    return false;
  }

  if (expectedType != type.getAsString()) {
    SmallString<256> buf;
    llvm::raw_svector_ostream os(buf);
    os << "Type of passed argument ";
    val.dumpToStream(os);
    os << " is of type "<< type.getAsString()
       << " which did not match expected " << expectedType << " for modifier '"
       << modifier << "' at offset " << offset + 1 << ".";
    BugReport *R = new BugReport(*InvalidTypeBugType, os.str(), C.addTransition());
    R->markInteresting(val);
    C.emitReport(R);
    return false;
  }
  return true;
}

bool PHPZPPChecker::checkArgs(const StringRef &format_spec,
                                  unsigned &offset, const unsigned numArgs,
                                  const CallEvent &Call,
                                  CheckerContext &C) const {
  // Call.dump();
  for (StringRef::const_iterator modifier = format_spec.begin(),
                                 last_mod = format_spec.end();
       modifier != last_mod; ++modifier) {
//std::cout << "  I am checking for " << *modifier << std::endl;
    const PHPTypeRange range = map.equal_range(*modifier);

    if (range.first == range.second) {
      SmallString<32> buf;
      llvm::raw_svector_ostream os(buf);
      os << "Unknown modifier '" << *modifier << "'";
      BugReport *R =
          new BugReport(*InvalidModifierBugType, os.str(), C.addTransition());
      C.emitReport(R);
      return false;
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
        SmallString<255> buf;
        llvm::raw_svector_ostream os(buf);
        os << "Too few arguments for format \"" << format_spec
           << "\" while checking for modifier '" << *modifier << "'.";
        BugReport *R = new BugReport(*WrongArgumentNumberBugType, os.str(),
                                     C.addTransition());
        C.emitReport(R);
//std::cout << "!!!!I am missing args! " << numArgs << "<=" << offset << std::endl;
        return false;
      }

      const SVal val = Call.getArgSVal(offset);
      if (!compareTypeWithSVal(offset, *modifier, val, *type->second, C)) {
        // TODO: Move error reporting here?

        // Even if there is a type mismatch we can continue, most of the time
        // this should be a simple mistake by the user, in rare cases the user
        // missed an argument and will get many subsequent errors
      }

    }
  }
  return true;
}

void PHPZPPChecker::checkPreCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  initIdentifierInfo(C.getASTContext());

  if (!Call.isGlobalCFunction())
    return;

  const IdentifierInfo *callee = Call.getCalleeIdentifier();
  if (callee != IIzpp && callee && IIzpp_ex && callee != IIzpmp &&
      callee != IIzpmp_ex) {
    return;
  }

  const FunctionDecl *decl = cast<FunctionDecl>(Call.getDecl());
  // we want the offset to be the last required argument which is the format
  // string, offset is 0-based, thus -1
  unsigned offset = decl->getMinRequiredArguments() - 1;

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

  if (!checkArgs(format_spec, offset, numArgs, Call, C))
    return;

  if (numArgs > 1 + offset) {
    SmallString<32> buf;
    llvm::raw_svector_ostream os(buf);
    os << "Too many arguments, modifier \"" << format_spec << "\" requires "
       << offset - decl->getMinRequiredArguments() + 1 << " arguments.";
    BugReport *R =
        new BugReport(*WrongArgumentNumberBugType, os.str(), C.addTransition());
    R->markInteresting(Call.getArgSVal(offset));
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
}

static void initPHPChecker(CheckerManager &mgr) {
  PHPZPPChecker *checker = mgr.registerChecker<PHPZPPChecker>();
  switch (mgr.getAnalyzerOptions().getOptionAsInteger("php-zpp-version", 1)) {
  case 1:
    checker->setMap(fillMapPHP55);
    break;
  case 2:
    checker->setMap(fillMapPHPSample);
    break;
  default:
    // TODO: ERROR
    break;
  }
}


extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker(initPHPChecker, "php.ZPPChecker",
                      "Check zend_parse_parameters usage");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
