//=== IntegerOverflowChecker.cpp - integer overflows checker ----*- C++ -*-===//
//
//           The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// \brief This defines IntegerOverflowChecker, which checks arithmetic
/// operations for integer overflows. This check corresponds to CWE-190.
///
//===----------------------------------------------------------------------===//
//
// Check for overflow performs by checkAdd(), checkSub() and checkMul()
// functions. checkAdd() and checkSub() consist of two parts for signed integer
// overflow check and unsigned integer overflow check(wraparound).
//
// Couple of heuristics were added for FP suppressing. USubHeuristic prevents
// warnings for intentional integer overflow while getting i.e UINT_MAX by
// subtracting 1U from 0U. GlobalsMembersHeuristic suppresses warning if
// arguments of arithmetic operation are global variables or class members.
// Sometimes CSA fails to determine right value for that type of arguments and
// inter-unit analysis assumed to be the best solution of this problem.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"

using namespace clang;
using namespace ento;
using namespace nonloc;

namespace {

class IntegerOverflowChecker : public Checker<check::PostStmt<BinaryOperator>,
                                              check::PostStmt<CXXNewExpr>,
                                              check::PostStmt<CallExpr>,
                                              check::PostStmt<MemberExpr>,
                                              check::Bind> {
  mutable std::unique_ptr<BuiltinBug> BT_Def, BT_Undef;

  /// Stores SourceLocations in which overflows happened for reducing the amount
  /// of equivalent warnings.
  mutable std::set<SourceLocation> OverflowLoc;

  struct IntegerOverflowFilter {
    DefaultBool CheckIntegerOverflowDef;
    DefaultBool CheckIntegerOverflowUndef;
    CheckName CheckNameIntegerOverflowDef;
    CheckName CheckNameIntegerOverflowUndef;
  };

  void reportBug(const std::string &Msg, CheckerContext &C,
                 const SourceLocation &SL, bool isUndef) const;

  std::string composeMsg(ProgramStateRef StateNotOverflow, const SVal &Lhs,
                         const SVal &Rhs, const Expr *ExprLhs,
                         const Expr *ExprRhs, bool isSigned, bool isOverflow,
                         BinaryOperator::Opcode *Op, CheckerContext &C) const;

  /// Check if addition of \p Lhs and \p Rhs can overflow.
  Optional<DefinedOrUnknownSVal> checkAdd(CheckerContext &C, const SVal &Lhs,
                                          const SVal &Rhs, QualType BinType,
                                          bool &isOverflow) const;

  /// Check if subtraction of \p Lhs and \p Rhs can overflow.
  Optional<DefinedOrUnknownSVal> checkSub(CheckerContext &C, const SVal &Lhs,
                                          const SVal &Rhs,
                                          const QualType &BinType,
                                          bool &isOverflow) const;

  /// Check if multiplication of \p Lhs and \p Rhs can overflow.
  Optional<DefinedOrUnknownSVal> checkMul(CheckerContext &C, const SVal &Lhs,
                                          const SVal &Rhs,
                                          const QualType &BinType,
                                          bool &isOverflow) const;

  /// \returns dump and constraints of \p Val.
  std::string getSymbolInformation(const SVal &Val, const Expr *E,
                                   CheckerContext &C) const;

  /// We ignore intentional underflow because of subtracting X from zero - the
  /// minimum unsigned value.
  bool makeUSubHeuristics(const BinaryOperator *BO) const;

  /// \returns true if there are suspicions that the actual value might be lose
  /// by analyzer.
  bool makeGlobalsMembersHeuristics(const SVal &Val, const Stmt *S,
                                    CheckerContext &C) const;

  /// Check if \p S should be ignored when participates in overflow.
  bool hasGlobalVariablesOrMembers(const Stmt *S, CheckerContext &C) const;

  /// Check if \p SE should be ignored when participates in overflow.
  bool hasGlobalVariablesOrMembers(const SymExpr *SE, CheckerContext &C) const;

  ProgramStateRef addToWhiteList(const Stmt *S, ProgramStateRef State,
                                 const LocationContext *LCtx) const;

  inline ProgramStateRef addToWhiteList(const SVal &SV,
                                        ProgramStateRef State) const;

  bool isInWhiteList(const Stmt *S, ProgramStateRef State,
                     const LocationContext *LCtx) const;

  inline bool isInWhiteList(const SVal &Val, ProgramStateRef State) const;

public:
  IntegerOverflowFilter Filter;

  /// Check addition, multiplication, and subtraction for overflow.
  void checkPostStmt(const BinaryOperator *B, CheckerContext &C) const;

  /// Contains check for new[].
  void checkPostStmt(const CXXNewExpr *NE, CheckerContext &C) const;

  /// Note if value returned by a call should be ignored when participates in
  /// overflow.
  void checkPostStmt(const CallExpr *CE, CheckerContext &C) const;

  /// Make MemberExpr ignored.
  void checkPostStmt(const MemberExpr *ME, CheckerContext &C) const;

  /// Note if value which is handled by checkBind should be ignored when
  /// participates in overflow.
  void checkBind(const SVal &Loc, const SVal &Val, const Stmt *S,
                 CheckerContext &C) const;
};
} // end anonymous namespace

/// WhiteList stores symbols change of which can be missed by analyzer.
REGISTER_LIST_WITH_PROGRAMSTATE(WhiteList, SVal)

void IntegerOverflowChecker::reportBug(const std::string &Msg,
                                       CheckerContext &C,
                                       const SourceLocation &SL,
                                       bool isUndef) const {
  if (const ExplodedNode *N = C.generateSink(C.getState())) {
    if (isUndef && !BT_Undef)
      BT_Undef.reset(new BuiltinBug(
          Filter.CheckNameIntegerOverflowUndef, "Integer overflow",
          "Arithmetic operation resulted in an overflow"));
    else if (!isUndef && !BT_Def)
      BT_Def.reset(
          new BuiltinBug(Filter.CheckNameIntegerOverflowDef, "Integer overflow",
                         "Arithmetic operation resulted in an overflow"));

    BuiltinBug *BT =
        static_cast<BuiltinBug *>((isUndef ? BT_Undef : BT_Def).get());
    C.emitReport(llvm::make_unique<BugReport>(*BT, Msg, N));
    OverflowLoc.insert(SL);
  }
}

std::string
IntegerOverflowChecker::composeMsg(ProgramStateRef StateNotOverflow,
                                   const SVal &Lhs, const SVal &Rhs,
                                   const Expr *ExprLhs, const Expr *ExprRhs,
                                   bool isSigned, bool isOverflow,
                                   BinaryOperator::Opcode *Op,
                                   CheckerContext &C) const {
  std::string Msg;
  std::string ErrorType = (!Op || isOverflow) ? "Overflow" : "Underflow";
  if (StateNotOverflow) {
    Msg.assign("Possible integer " + ErrorType + ": ");
    if (C.getState()->isTainted(Lhs))
      Msg.append("left operand is tainted. ");
    else
      Msg.append("right operand is tainted. ");
  } else {
    if (isSigned)
      Msg.assign("Undefined behavior: ");

    Msg.append("Integer " + ErrorType + ". ");
  }
  std::string Operation, Preposition;

  if (!Op || *Op == BO_Mul || *Op == BO_MulAssign) {
    Operation = "Multiplication of ";
    Preposition = " with ";
  } else if (*Op == BO_Add || *Op == BO_AddAssign) {
    Operation = "Addition of ";
    Preposition = " with ";
  } else {
    Operation = "Subtraction of ";
    Preposition = " from ";
  }

  if (Op && (*Op == BO_Sub || (*Op == BO_SubAssign)))
    Msg.append(Operation + getSymbolInformation(Rhs, ExprRhs, C) + Preposition +
               getSymbolInformation(Lhs, ExprLhs, C));
  else
    Msg.append(Operation + getSymbolInformation(Lhs, ExprLhs, C) + Preposition +
               getSymbolInformation(Rhs, ExprRhs, C));

  if (!Op)
    Msg.append(" while memory allocation.");

  return Msg;
}

Optional<DefinedOrUnknownSVal>
IntegerOverflowChecker::checkAdd(CheckerContext &C, const SVal &Lhs,
                                 const SVal &Rhs, QualType BinType,
                                 bool &isOverflow) const {
  SVal CondOverflow;
  ProgramStateRef State = C.getState();
  SValBuilder &SvalBuilder = C.getSValBuilder();
  SVal NullSval = SvalBuilder.makeZeroVal(BinType);
  QualType CondType = SvalBuilder.getConditionType();
  SVal ValArgSum = SvalBuilder.evalBinOp(State, BO_Add, Lhs, Rhs, BinType);
  if (BinType->isSignedIntegerType()) {
    // For positive operands
    // rhs > 0
    SVal CondRhsGtNull = SvalBuilder.evalBinOp(State, BO_GT, Rhs, NullSval,
                                               CondType);
    // lhs > 0
    SVal CondLhsGtNull = SvalBuilder.evalBinOp(State, BO_GT, Lhs, NullSval,
                                               CondType);
    // rhs > 0 && lhs > 0
    SVal CondArgsGtNull = SvalBuilder.evalBinOp(State, BO_And, CondRhsGtNull,
                                                CondLhsGtNull, CondType);
    // lhs+rhs<=0
    SVal CondArgSumLtNull = SvalBuilder.evalBinOp(State, BO_LE, ValArgSum,
                                                  NullSval, CondType);

    SVal CondPositiveOverflow =
        SvalBuilder.evalBinOp(State, BO_And, CondArgsGtNull, CondArgSumLtNull,
                              CondType);
    // For negative operands
    // lhs < 0
    SVal CondLhsLtNull = SvalBuilder.evalBinOp(State, BO_LT, Rhs, NullSval,
                                               CondType);
    // rhs < 0
    SVal CondRhsLtNull = SvalBuilder.evalBinOp(State, BO_LT, Lhs, NullSval,
                                               CondType);
    // rhs < 0 && lhs < 0
    SVal CondArgsLtNull = SvalBuilder.evalBinOp(State, BO_And, CondLhsLtNull,
                                                CondRhsLtNull, CondType);

    // lhs+rhs>=0
    SVal CondArgSumGtNull = SvalBuilder.evalBinOp(State, BO_GE, ValArgSum,
                                                  NullSval, CondType);

    SVal CondNegativeOverflow =
        SvalBuilder.evalBinOp(State, BO_And, CondArgsLtNull, CondArgSumGtNull,
                              CondType);
    if (!CondPositiveOverflow.isZeroConstant())
      isOverflow = true;

    CondOverflow = SvalBuilder.evalBinOp(State, BO_Or, CondPositiveOverflow,
                                         CondNegativeOverflow, CondType);
  } else {
    isOverflow = true;
    // lhs > sum
    SVal CondLhsGtArgSum = SvalBuilder.evalBinOp(State, BO_GT, Lhs, ValArgSum,
                                                 CondType);
    // rhs > sum
    SVal CondRhsGtArgSum = SvalBuilder.evalBinOp(State, BO_GT, Rhs, ValArgSum,
                                                 CondType);
    // lhs > sum && rhs > sum
    CondOverflow = SvalBuilder.evalBinOp(State, BO_And, CondLhsGtArgSum,
                                         CondRhsGtArgSum, CondType);
  }

  return CondOverflow.getAs<DefinedOrUnknownSVal>();
}

Optional<DefinedOrUnknownSVal>
IntegerOverflowChecker::checkSub(CheckerContext &C, const SVal &Lhs,
                                 const SVal &Rhs, const QualType &BinType,
                                 bool &isOverflow) const {
  SVal CondOverflow;
  ProgramStateRef State = C.getState();
  SValBuilder &SvalBuilder = C.getSValBuilder();
  SVal NullSval = SvalBuilder.makeZeroVal(BinType);
  QualType CondType = SvalBuilder.getConditionType();
  SVal ValArgSub = SvalBuilder.evalBinOp(State, BO_Sub, Lhs, Rhs, BinType);
  if (BinType->isSignedIntegerType()) {
    // When first operand is negative
    // lhs < 0
    SVal CondLhsLtNull = SvalBuilder.evalBinOp(State, BO_LT, Lhs, NullSval,
                                               CondType);
    // rhs > 0
    SVal CondRhsGtNull = SvalBuilder.evalBinOp(State, BO_GT, Rhs, NullSval,
                                               CondType);
    // rhs > 0 && lhs < 0
    SVal CondLhsLtNullRhsGtNull =
        SvalBuilder.evalBinOp(State, BO_And, CondLhsLtNull, CondRhsGtNull,
                              CondType);
    // lhs - rhs >= 0
    SVal CondArgSubGeNull = SvalBuilder.evalBinOp(State, BO_GE, ValArgSub,
                                                  NullSval, CondType);

    // rhs > 0 && lhs < 0 && lhs-rhs >= 0
    SVal CondNegativeOverflow =
        SvalBuilder.evalBinOp(State, BO_And, CondLhsLtNullRhsGtNull,
                              CondArgSubGeNull, CondType);

    // When first operand is positive
    // lhs > 0
    SVal CondLhsGtNull = SvalBuilder.evalBinOp(State, BO_GT, Lhs, NullSval,
                                               CondType);
    // rhs < 0
    SVal CondRhsLtNull = SvalBuilder.evalBinOp(State, BO_LT, Rhs, NullSval,
                                               CondType);
    // rhs < 0 && lhs > 0
    SVal CondLhsGtNullRhsLtNull =
        SvalBuilder.evalBinOp(State, BO_And, CondLhsGtNull, CondRhsLtNull,
                              CondType);
    // lhs - rhs <= 0
    SVal CondArgSubLeNull = SvalBuilder.evalBinOp(State, BO_LE, ValArgSub,
                                                  NullSval, CondType);

    // rhs < 0 && lhs > 0 && lhs - rhs <= 0
    SVal CondPositiveOverflow =
        SvalBuilder.evalBinOp(State, BO_And, CondLhsGtNullRhsLtNull,
                              CondArgSubLeNull, CondType);

    CondOverflow = SvalBuilder.evalBinOp(State, BO_Or, CondNegativeOverflow,
                                         CondPositiveOverflow, CondType);
    if (!CondPositiveOverflow.isZeroConstant())
      isOverflow = true;
  } else
    CondOverflow = SvalBuilder.evalBinOp(State, BO_LT, Lhs, Rhs, CondType);

  return CondOverflow.getAs<DefinedOrUnknownSVal>();
}

Optional<DefinedOrUnknownSVal>
IntegerOverflowChecker::checkMul(CheckerContext &C, const SVal &Lhs,
                                 const SVal &Rhs, const QualType &BinType,
                                 bool &isOverflow) const {
  ProgramStateRef State = C.getState();
  ProgramStateRef CondNotOverflow, CondPossibleOverflow;
  SValBuilder &SvalBuilder = C.getSValBuilder();
  SVal NullSval = SvalBuilder.makeZeroVal(BinType);
  QualType CondType = SvalBuilder.getConditionType();

  // lhs == 0
  SVal LhsNotNull = SvalBuilder.evalBinOp(State, BO_NE, Lhs, NullSval,
                                          CondType);

  // rhs == 0
  SVal RhsNotNull = SvalBuilder.evalBinOp(State, BO_NE, Rhs, NullSval,
                                          CondType);

  Optional<DefinedOrUnknownSVal> CondOverflow =
      SvalBuilder.evalBinOp(State, BO_And, LhsNotNull, RhsNotNull, CondType)
          .getAs<DefinedOrUnknownSVal>();

  if (!CondOverflow.hasValue())
    return CondOverflow;

  std::tie(CondPossibleOverflow, CondNotOverflow) =
      State->assume(*CondOverflow);

  if (CondNotOverflow && CondPossibleOverflow)
    return CondOverflow;

  if (CondPossibleOverflow) {
    // lhs * rhs
    SVal ValMulti = SvalBuilder.evalBinOp(State, BO_Mul, Lhs, Rhs, BinType);
    // First operand(lhs) is not 0
    // (lhs * rhs)/lhs
    SVal ValDiv = SvalBuilder.evalBinOp(State, BO_Div, ValMulti, Lhs, BinType);
    // (lhs * rhs)/lhs != rhs

    CondOverflow = SvalBuilder.evalBinOp(State, BO_NE, ValDiv, Rhs, CondType)
                       .getAs<DefinedOrUnknownSVal>();
  }

  isOverflow = BinType->isUnsignedIntegerOrEnumerationType() ||
               SvalBuilder.evalBinOp(State, BO_LT, Lhs, NullSval, CondType)
                       .isZeroConstant() ==
                   SvalBuilder.evalBinOp(State, BO_LT, Rhs, NullSval, CondType)
                       .isZeroConstant();

  return CondOverflow;
}

std::string
IntegerOverflowChecker::getSymbolInformation(const SVal &Val, const Expr *E,
                                             CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  std::string StreamRangeStr, SValDumpStr;
  llvm::raw_string_ostream StreamRange(StreamRangeStr), SValDump(SValDumpStr);
  Val.dumpToStream(SValDump);
  if (Val.getSubKind() == SymbolValKind) {
    State->getConstraintManager().print(State, StreamRange, "\n", "\n");
    StreamRange.flush();
    size_t from = StreamRangeStr.find(SValDump.str() + " : ");
    if (from != std::string::npos) {
      size_t to = StreamRangeStr.find("\n", from);
      from += SValDump.str().length();
      SValDump.str().append(StreamRangeStr.substr(from, to - from));
    }
  }
  if (!E || isa<IntegerLiteral>(E->IgnoreParenCasts()))
    return SValDump.str();

  E = E->IgnoreParens();
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E))
    if ((UO->getOpcode() == UO_Plus || UO->getOpcode() == UO_Minus) &&
        isa<IntegerLiteral>(UO->getSubExpr()))
      return SValDump.str();

  SValDump << " (";
  E->printPretty(SValDump, 0, C.getASTContext().getPrintingPolicy());
  SValDump << ")";

  return SValDump.str();
}

// We ignore intentional underflow with subtracting X from zero - the minimal
// unsigned value.
bool
IntegerOverflowChecker::makeUSubHeuristics(const BinaryOperator *BO) const {
  const Expr *ExprLhs = BO->getLHS()->IgnoreParenCasts();
  if (isa<IntegerLiteral>(ExprLhs)) {
    const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(ExprLhs);
    return IL->getValue().isMinValue();
  }
  return false;
}

bool
IntegerOverflowChecker::makeGlobalsMembersHeuristics(const SVal &Val,
                                                     const Stmt *S,
                                                     CheckerContext &C)const {
  if (Val.isConstant()) {
    bool good = isInWhiteList(Val, C.getState()) &&
                (S->getStmtClass() != Stmt::IntegerLiteralClass) &&
                (S->getStmtClass() != Stmt::ImplicitCastExprClass);
    return good ? true : hasGlobalVariablesOrMembers(S, C);
  } else if (const SymExpr *SE = Val.getAsSymExpr())
    return isInWhiteList(Val, C.getState()) ? true
                                            : hasGlobalVariablesOrMembers(SE, C);
  else if (const MemRegion *Mem = Val.getAsRegion())
    return isInWhiteList(Val, C.getState()) || isa<FieldRegion>(Mem) ||
           Mem->hasGlobalsOrParametersStorage();

  return false;
}

bool
IntegerOverflowChecker::hasGlobalVariablesOrMembers(const Stmt *S,
                                                    CheckerContext &C) const {
  if (S == NULL || S->getStmtClass() == Stmt::IntegerLiteralClass)
    return false;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  if ((S->getStmtClass() != Stmt::ImplicitCastExprClass) &&
      isInWhiteList(S, State, LCtx))
    return true;

  if (const MemberExpr *MExpr = dyn_cast<MemberExpr>(S)) {
    if (MExpr->getMemberDecl()->isFunctionOrFunctionTemplate())
      return hasGlobalVariablesOrMembers(MExpr->getMemberDecl()->getBody(), C);
    // We found member usage!
    return true;
  }

  if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(S))
    if (isa<DeclRefExpr>(ICE->getSubExpr()) && isInWhiteList(C.getSVal(ICE),
                                                             State))
        return true;

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S))
    if (const VarDecl *VarD = dyn_cast<VarDecl>(DRE->getDecl())) {
      Loc VLoc = C.getStoreManager().getLValueVar(VarD, LCtx);
      SVal VVal = C.getStoreManager().getBinding(State->getStore(), VLoc);
      if (isInWhiteList(VVal, State))
        return true;
    }

  // We will not surrender!
  for (auto I = S->child_begin(); I != S->child_end(); I++)
    if (hasGlobalVariablesOrMembers(*I, C))
      return true;

  return false;
}

bool
IntegerOverflowChecker::hasGlobalVariablesOrMembers(const SymExpr *SE,
                                                    CheckerContext &C) const {
  WhiteListTy ES = C.getState()->get<WhiteList>();
  for (auto I = ES.begin(); I != ES.end(); ++I) {
    SVal Val = *I;
    SymbolRef SR = Val.getAsSymbol();
    if (SR == SE)
      return true;
  }
  // SymbolCast
  if (const SymbolCast *SC = dyn_cast<SymbolCast>(SE))
    return hasGlobalVariablesOrMembers(SC->getOperand(), C);
  // BinarySymExpr
  if (const IntSymExpr *ISE = dyn_cast<IntSymExpr>(SE))
    return hasGlobalVariablesOrMembers(ISE->getRHS(), C);
  if (const SymIntExpr *SIE = dyn_cast<SymIntExpr>(SE))
    return hasGlobalVariablesOrMembers(SIE->getLHS(), C);
  if (const SymSymExpr *SSE = dyn_cast<SymSymExpr>(SE))
    return (hasGlobalVariablesOrMembers(SSE->getLHS(), C) ||
            hasGlobalVariablesOrMembers(SSE->getRHS(), C));
  // SymbolData
  if (const SymbolRegionValue *SRV = dyn_cast<SymbolRegionValue>(SE)) {
    const TypedValueRegion *TVR = SRV->getRegion();
    return isa<FieldRegion>(TVR) || TVR->hasGlobalsOrParametersStorage();
  }
  if (const SymbolDerived *SD = dyn_cast<SymbolDerived>(SE)) {
    const TypedValueRegion *TVR = SD->getRegion();
    return isa<FieldRegion>(TVR) || TVR->hasGlobalsOrParametersStorage();
  }
  if (const SymbolConjured *SC = dyn_cast<SymbolConjured>(SE))
    return hasGlobalVariablesOrMembers(SC->getStmt(), C);

  return false;
}

ProgramStateRef
IntegerOverflowChecker::addToWhiteList(const Stmt *S, ProgramStateRef State,
                                       const LocationContext *LCtx) const {
  if (const Expr *E = dyn_cast_or_null<Expr>(S))
    S = E->IgnoreParens();
  return addToWhiteList(State->getSVal(S, LCtx), State);
}

inline ProgramStateRef
IntegerOverflowChecker::addToWhiteList(const SVal &Val,
                                       ProgramStateRef State) const {
  return State->get<WhiteList>().contains(Val) ? State
                                               : State->add<WhiteList>(Val);
}

bool IntegerOverflowChecker::isInWhiteList(const Stmt *S, ProgramStateRef State,
                                           const LocationContext *LCtx) const {
  if (const Expr *E = dyn_cast_or_null<Expr>(S))
    S = E->IgnoreParens();
  return isInWhiteList(State->getSVal(S, LCtx), State);
}

inline bool IntegerOverflowChecker::isInWhiteList(const SVal &V,
                                                  ProgramStateRef State) const {
  return State->get<WhiteList>().contains(V);
}

void IntegerOverflowChecker::checkPostStmt(const BinaryOperator *B,
                                           CheckerContext &C) const {
  if (OverflowLoc.find(B->getExprLoc()) != OverflowLoc.end())
    return;

  if (!B->getLHS()->getType()->isIntegerType() ||
      !B->getRHS()->getType()->isIntegerType())
    return;

  ProgramStateRef State = C.getState();
  QualType BinType = B->getType();
  const Expr *ExprLhs = B->getLHS();
  const Expr *ExprRhs = B->getRHS();
  SVal Lhs = C.getSVal(ExprLhs);
  SVal Rhs = C.getSVal(ExprRhs);

  if (makeGlobalsMembersHeuristics(Lhs, ExprLhs, C)) {
    C.addTransition(addToWhiteList(Lhs, State));
    return;
  }
  if (makeGlobalsMembersHeuristics(Rhs, ExprRhs, C)) {
    C.addTransition(addToWhiteList(Rhs, State));
    return;
  }

  if (!Filter.CheckIntegerOverflowDef && BinType->isUnsignedIntegerType())
    return;

  if (!Filter.CheckIntegerOverflowUndef && BinType->isSignedIntegerType())
    return;

  BinaryOperator::Opcode Op = B->getOpcode();
  if (Op != BO_Add && Op != BO_Mul && Op != BO_Sub && Op != BO_AddAssign &&
      Op != BO_MulAssign && Op != BO_SubAssign)
    return;

  Optional<DefinedOrUnknownSVal> CondOverflow;
  ProgramStateRef StateOverflow, StateNotOverflow;

  bool isOverflow = false;
  if (Op == BO_Add || Op == BO_AddAssign)
    CondOverflow = checkAdd(C, Lhs, Rhs, BinType, isOverflow);
  else if (Op == BO_Sub || Op == BO_SubAssign) {
    if ((BinType->isUnsignedIntegerType()) && makeUSubHeuristics(B))
      return;
    CondOverflow = checkSub(C, Lhs, Rhs, BinType, isOverflow);
  } else if (Op == BO_Mul || Op == BO_MulAssign)
    CondOverflow = checkMul(C, Lhs, Rhs, BinType, isOverflow);

  if (!CondOverflow)
    return;

  std::tie(StateOverflow, StateNotOverflow) = State->assume(*CondOverflow);

  if (!StateOverflow ||
      (StateNotOverflow && !(State->isTainted(Lhs) || State->isTainted(Rhs))))
    return;

  std::string Msg = composeMsg(StateNotOverflow, Lhs, Rhs, ExprLhs, ExprRhs,
                               B->getType()->isSignedIntegerOrEnumerationType(),
                               isOverflow, &Op, C);

  reportBug(Msg, C, B->getExprLoc(), BinType->isSignedIntegerType());
}

void IntegerOverflowChecker::checkPostStmt(const CXXNewExpr *NewExpr,
                                           CheckerContext &C) const {
  if (!Filter.CheckIntegerOverflowDef)
    return;

  if (NewExpr->getOperatorNew()->getOverloadedOperator() != OO_Array_New)
    return;

  const Expr *ArrSize = NewExpr->getArraySize();
  SVal ElementCount = C.getSVal(ArrSize);
  ProgramStateRef State = C.getState();

  if (makeGlobalsMembersHeuristics(ElementCount, ArrSize, C)) {
    C.addTransition(addToWhiteList(ElementCount, State));
    return;
  }

  QualType NewExprType = NewExpr->getAllocatedType();
  uint64_t NewExprTypeSize = C.getASTContext().getTypeSizeInChars(NewExprType)
                                              .getQuantity();
  SValBuilder &SvalBuilder = C.getSValBuilder();
  SVal NewExprTypeSizeVal = SvalBuilder.makeIntVal(NewExprTypeSize, true);

  bool isOverflow;
  Optional<DefinedOrUnknownSVal> CondOverflow = checkMul(C, NewExprTypeSizeVal,
                                                         ElementCount,
                                                         ArrSize->getType(),
                                                         isOverflow);

  if (!CondOverflow)
    return;

  ProgramStateRef StateOverflow, StateNotOverflow;
  std::tie(StateOverflow, StateNotOverflow) = State->assume(*CondOverflow);

  if (!StateOverflow || (StateNotOverflow && !State->isTainted(ElementCount)))
    return;

  std::string Msg = composeMsg(StateNotOverflow, NewExprTypeSizeVal,
                               ElementCount, 0, ArrSize, false, isOverflow, 0,
                               C);

  reportBug(Msg, C, NewExpr->getExprLoc(), false);
}

void IntegerOverflowChecker::checkPostStmt(const CallExpr *CE,
                                           CheckerContext &C) const {
  if (makeGlobalsMembersHeuristics(C.getSVal(CE), CE, C))
    C.addTransition(addToWhiteList(CE, C.getState(), C.getLocationContext()));
}

void IntegerOverflowChecker::checkPostStmt(const MemberExpr *ME,
                                           CheckerContext &C) const {
  C.addTransition(addToWhiteList(ME, C.getState(), C.getLocationContext()));
}

void IntegerOverflowChecker::checkBind(const SVal &Loc, const SVal &Val,
                                       const Stmt *S, CheckerContext &C) const {
  if (makeGlobalsMembersHeuristics(Val, S, C))
    C.addTransition(addToWhiteList(Val, C.getState()));
}

#define REGISTER_CHECKER(name)                                                 \
  void ento::register##name(CheckerManager &mgr) {                             \
    IntegerOverflowChecker *checker =                                          \
        mgr.registerChecker<IntegerOverflowChecker>();                         \
    checker->Filter.Check##name = true;                                        \
    checker->Filter.CheckName##name = mgr.getCurrentCheckName();               \
  }

REGISTER_CHECKER(IntegerOverflowDef)
REGISTER_CHECKER(IntegerOverflowUndef)
