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

#include <cassert>

using namespace clang;
using namespace ento;

#ifdef DEBUG_PHP_ZPP_CHECKER
#define debug_stream llvm::outs()
#else
#define debug_stream llvm::nulls()
#endif

#define MAPPING(format, type, pointer_level)                                   \
  map.insert(PHPTypeMap::value_type(                                           \
      (format), PHPNativeType((type), sizeof(pointer_level) - 1)))
#define MAPPING_EMPTY(format)                                                  \
  map.insert(std::pair<char, const PHPNativeType>((format), PHPNativeType()))

namespace {
class PHPNativeType {
  const StringRef name;
  const bool hasVal;
  int pointerLevel;

public:
  PHPNativeType() : hasVal(false) {}
  PHPNativeType(const StringRef &name, int pointerLevel = 0)
      : name(name), hasVal(true), pointerLevel(pointerLevel) {}

  const StringRef &getName() const {
    assert(hasVal);
    return name;
  }

  int getPointerLevel() const {
    return pointerLevel;
  }

  operator bool() const { return hasVal; }
};

typedef std::multimap<char, const PHPNativeType> PHPTypeMap;
typedef std::pair<const PHPTypeMap::const_iterator,
                  const PHPTypeMap::const_iterator> PHPTypeRange;

// These mappings map a zpp modifier to underlying types. The second argument
// refers to the indirectionlevel, mind: zpp receives the address of the object
// to store in wich adds a level.
// Some types return multiple values, these are added multiple times inorder to
// this list (i.e. a string "s" consists of a char array and length)
static void fillMapPHPBase(PHPTypeMap &map) {
  MAPPING('a', "zval", "**");
  MAPPING('A', "zval", "**");
  MAPPING('b', "zend_bool", "*");
  MAPPING('C', "zend_class_entry", "**");
  MAPPING('d', "double", "*");
  MAPPING('f', "zend_fcall_info", "*");
  MAPPING('f', "zend_fcall_info_cache", "*");
  MAPPING('h', "HashTable", "**");
  MAPPING('H', "HashTable", "**");
  MAPPING('o', "zval", "**");
  MAPPING('O', "zval", "**");
  MAPPING('O', "zend_class_entry", "*");
  MAPPING('r', "zval", "**");
  MAPPING('z', "zval", "**");
  MAPPING('Z', "zval", "***");
  MAPPING_EMPTY('|');
  MAPPING_EMPTY('/');
  MAPPING_EMPTY('!');
  MAPPING('+', "zval", "****");
  MAPPING('+', "int", "*");
  MAPPING('*', "zval", "****");
  MAPPING('*', "int", "*");
}

static void fillMapPHP55(PHPTypeMap &map) {
  fillMapPHPBase(map);
  MAPPING('l', "long", "*");
  MAPPING('L', "long", "*");
  MAPPING('p', "char", "**");
  MAPPING('p', "int", "*");
  MAPPING('s', "char", "**");
  MAPPING('s', "int", "*");
}

static void fillMapPHPSizeTInt64(PHPTypeMap &map) {
  fillMapPHPBase(map);
  MAPPING('i', "zend_int_t", "*");
  MAPPING('I', "zend_int_t", "*");
  MAPPING('P', "char", "**");
  MAPPING('P', "zend_size_t", "*");
  MAPPING('S', "char", "**");
  MAPPING('S', "zend_size_t", "*");
}

class PHPZPPChecker
    : public Checker<check::PreCall, check::ASTDecl<TypedefDecl> > {
  mutable IdentifierInfo *IIzpp, *IIzpp_ex, *IIzpmp, *IIzpmp_ex;

  OwningPtr<BugType> InvalidTypeBugType;
  OwningPtr<BugType> InvalidModifierBugType;
  OwningPtr<BugType> WrongArgumentNumberBugType;

  PHPTypeMap map;

  typedef std::map<const StringRef, const QualType> TypedefMap;
  mutable TypedefMap typedefs;

  void initIdentifierInfo(ASTContext &Ctx) const;

  const StringLiteral *getCStringLiteral(const SVal val) const;
  bool compareTypeWithSVal(unsigned offset, char modifier, const SVal &val,
                           const PHPNativeType &expectedType,
                           CheckerContext &C) const;
  bool checkArgs(const StringRef &format_spec, unsigned &offset,
                 const unsigned numArgs, const CallEvent &Call,
                 CheckerContext &C) const;

public:
  PHPZPPChecker();

  typedef void (*MapFiller)(PHPTypeMap &);
  void setMap(MapFiller filler);
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkASTDecl(const TypedefDecl *td, AnalysisManager &Mgr,
                    BugReporter &BR) const;
};
}

#if (CLANG_VERSION_MAJOR == 3 && CLANG_VERSION_MINOR >= 5) || CLANG_VERSION_MAJOR > 3
/* XXX that probably shouldn't be NULL but a valid checker, */
# define CHECKER_CLASS NULL,
#else
# define CHECKER_CLASS
#endif

PHPZPPChecker::PHPZPPChecker()
    : IIzpp(0), IIzpp_ex(0), IIzpmp(0), IIzpmp_ex(0) {
  InvalidTypeBugType.reset(new BugType(CHECKER_CLASS "Invalid type", "PHP ZPP API Error"));

  InvalidModifierBugType.reset(
      new BugType(CHECKER_CLASS "Invalid modifier", "PHP ZPP API Error"));

  WrongArgumentNumberBugType.reset(
      new BugType(CHECKER_CLASS "Wrong number of zpp arguments", "PHP ZPP API Error"));
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
    return cast<TypedValueRegion>(region)->getLocationType();
  }
  if (isa<SymbolicRegion>(region)) {
    return cast<SymbolicRegion>(region)
        ->getSymbol()
        ->getType();
  }
  return QualType();
}

bool PHPZPPChecker::compareTypeWithSVal(unsigned offset, char modifier, const SVal &val,
                                            const PHPNativeType &expectedType,
                                            CheckerContext &C) const {
 
  const QualType initialType = getQualTypeForSVal(val);

  if (initialType.isNull()) {
    // TODO need a good way to report this, even though this is no error
    llvm::outs() << "Couldn't get type for argument at offset " << offset << "\n";
    val.dump();
    return false;
  }

  QualType type = initialType.getCanonicalType();

  int passedPointerLevel = 0;
  while (type->isPointerType()) {
    ++passedPointerLevel;
    type = type->getPointeeType();
  }

  bool match = false;
  const TypedefMap::const_iterator typedef_ = typedefs.find(expectedType.getName());
  if (typedef_ != typedefs.end()) {
    match = (type == typedef_->second.getCanonicalType());
  } else {
    match = (type.getAsString() == expectedType.getName());
  }

  if (!match) {
    SmallString<256> buf;
    llvm::raw_svector_ostream os(buf);
    os << "Type of passed argument ";
    val.dumpToStream(os);
    os << " is of type " << initialType.getAsString()
       << " which did not match expected " << expectedType.getName() << " ";
    for (int i = 0; i < expectedType.getPointerLevel(); ++i) {
      os << "*";
    }
    os << " for modifier '" << modifier << "' at offset " << offset + 1 << ".";
    BugReport *R =
        new BugReport(*InvalidTypeBugType, os.str(), C.addTransition());
    R->markInteresting(val);
    C.emitReport(R);
    return false;
  }

  if (passedPointerLevel != expectedType.getPointerLevel()) {
    SmallString<256> buf;
    llvm::raw_svector_ostream os(buf);
    os << "Pointer indirection level of passed argument ";
    val.dumpToStream(os);
    os << " is " << passedPointerLevel << " which did not match expected "
       << expectedType.getPointerLevel() << " for modifier '" << modifier
       << "' at offset " << offset + 1 << ".";
    BugReport *R =
        new BugReport(*InvalidTypeBugType, os.str(), C.addTransition());
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
  Call.dump(debug_stream);
  for (StringRef::const_iterator modifier = format_spec.begin(),
                                 last_mod = format_spec.end();
       modifier != last_mod; ++modifier) {
    debug_stream << "  I am checking for " << *modifier << "\n";
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
      debug_stream << "    I need a " << type->second.getName() << " (" << offset << ")\n";
      if (numArgs <= offset) {
        SmallString<255> buf;
        llvm::raw_svector_ostream os(buf);
        os << "Too few arguments for format \"" << format_spec
           << "\" while checking for modifier '" << *modifier << "'.";
        BugReport *R = new BugReport(*WrongArgumentNumberBugType, os.str(),
                                     C.addTransition());
        C.emitReport(R);
        debug_stream << "!!!!I am missing args! " << numArgs << "<=" << offset << "\n";
        return false;
      }

      const SVal val = Call.getArgSVal(offset);
      if (!compareTypeWithSVal(offset, *modifier, val, type->second, C)) {
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
    llvm::outs() << "Couldn't get format string looked at offset " << offset << "\n";
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

void PHPZPPChecker::checkASTDecl(const TypedefDecl *td, AnalysisManager &Mgr, BugReporter &BR) const {
  // This extra map might be quite inefficient, probably we should iterat over the delarations, later in
  // the check?
  // for (DeclContext::decl_iterator it = decl->getParent()->decls_begin(); it != decl->getParent()->decls_end(); ++it) { if (isa<TypedefDecl>(*it)) {

  typedefs.insert(std::pair<const StringRef, QualType>(td->getName(), td->getUnderlyingType()));
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
  long version = 1;
  const char *from_env = getenv("PHP_ZPP_CHECKER_VERSION");
  if (from_env) {
    version = strtol(from_env, NULL, 0);
  }
  PHPZPPChecker *checker = mgr.registerChecker<PHPZPPChecker>();
  switch (mgr.getAnalyzerOptions().getOptionAsInteger("php-zpp-version", version)) {
  case 1:
    checker->setMap(fillMapPHP55);
    break;
  case 2:
    checker->setMap(fillMapPHPSizeTInt64);
    break;
  default:
    // TODO: ERROR
    break;
  }
}


extern "C" CLANGPHPCHECKER_EXPORT void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker(initPHPChecker, "php.ZPPChecker",
                      "Check zend_parse_parameters usage");
}

extern "C" CLANGPHPCHECKER_EXPORT const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
