// RUN: %clang_cc1 -Wno-unused-value -Wno-integer-overflow -Wno-constant-conversion -analyze -analyzer-checker=alpha.different.IntegerOverflow,alpha.undefbehavior.IntegerOverflow,alpha.security.taint,core.DivideZero,deadcode,core.builtin %s -verify
#include "Inputs/system-header-simulator.h"

#define SHRT_MAX ((short)(~0U >> 1))
#define INT_MAX ((int)(~0U >> 1))
#define INT_MIN (-INT_MAX - 1)
#define UINT_MAX (~0U)
#define LONG_MAX ((long)(~0UL >> 1))
#define LONG_MIN (-LONG_MAX - 1)
#define ULONG_MAX (~0UL)
#define LLONG_MAX ((long long)(~0ULL >> 1))
#define LLONG_MIN (-LLONG_MAX - 1)
#define ULLONG_MAX (~0ULL)

char *strchr(const char *s, int c);
int randomInt();

// Addition : signed
void signAddEW_1(void) {
  INT_MAX + 1; // expected-warning{{Undefined behavior: Integer Overflow. Addition of 2147483647 S32b ((int)(~0U >> 1)) with 1 S32b}}
}
void signAddEW_2(void) {
  INT_MIN + INT_MIN; // expected-warning{{Undefined behavior: Integer Underflow. Addition of -2147483648 S32b (-((int)(~0U >> 1)) - 1) with -2147483648 S32b (-((int)(~0U >> 1)) - 1)}}
}
void signAddEW_3(void) {
  LONG_MAX + 1; // expected-warning{{Undefined behavior: Integer Overflow. Addition of 9223372036854775807 S64b ((long)(~0UL >> 1)) with 1 S64b}}
}
void signAddNW_4(void) {
  SHRT_MAX + 1; // no-warning
}
void signAddNW_5(int b) {
  if (b > INT_MAX)
    b + 3; // no-warning
}
void signAddEW_6(void) {
  int a = randomInt();
  if (a == INT_MAX)
    a + 2; // expected-warning{{Undefined behavior: Integer Overflow. Addition of 2147483647 S32b (a) with 2 S32b}}
  else if (a < INT_MAX)
    a + 2; // no-warning
}

// Addition : unsigned
void unsignAddEW_1(void) {
  UINT_MAX + 1; // expected-warning{{Integer Overflow. Addition of 4294967295 U32b (~0U) with 1 U32b}}
}
void unsignAddEW_2(void) {
  1 + (unsigned)-1; // expected-warning{{Integer Overflow. Addition of 1 U32b with 4294967295 U32b ((unsigned int)-1)}}
}
void unsignAddEW_3(void) {
  ULONG_MAX + 1; // expected-warning{{Integer Overflow. Addition of 18446744073709551615 U64b (~0UL) with 1 U64b}}
}

// Subtraction : signed
void signSubEW_1(void) {
  INT_MIN - 1; // expected-warning{{Undefined behavior: Integer Underflow. Subtraction of 1 S32b from -2147483648 S32b (-((int)(~0U >> 1)) - 1)}}
}
void signSubEW_2(void) {
  -INT_MAX - 2; // expected-warning{{Undefined behavior: Integer Underflow. Subtraction of 2 S32b from -2147483647 S32b (-((int)(~0U >> 1)))}}
}
void signSubNW_3(void) {
  -INT_MAX - 1; // no-warning
}
void signSubEW_4(void) {
  LONG_MIN - 1; // expected-warning{{Undefined behavior: Integer Underflow. Subtraction of 1 S64b from -9223372036854775808 S64b (-((long)(~0UL >> 1)) - 1)}}
}

// Subtraction : unsigned
void unsignSubNW_1(void) {
  0 - (unsigned)1; // no-warning
}
void unsignSubEW_2(void) {
  int a = 0;
  a - (unsigned)1; // expected-warning{{Integer Underflow. Subtraction of 1 U32b from 0 U32b (a)}}
}

// Multiplication : signed
void signMulEW_1(void) {
  (INT_MAX / 2) * 3; // expected-warning{{Undefined behavior: Integer Overflow. Multiplication of 1073741823 S32b (((int)(~0U >> 1)) / 2) with 3 S32b}}
}
void signMulNW_2(void) {
  INT_MAX * 0; // no-warning
}
void signMulNW_3(void) {
  0 * INT_MAX; // no-warning
}
void signMulEW_4(void) {
  INT_MIN *(-1); // expected-warning{{Undefined behavior: Integer Overflow. Multiplication of -2147483648 S32b (-((int)(~0U >> 1)) - 1) with -1 S32b}}
}
void signMulEW_5(void) {
  (LONG_MAX / 2) * 3; // expected-warning{{Undefined behavior: Integer Overflow. Multiplication of 4611686018427387903 S64b (((long)(~0UL >> 1)) / 2) with 3 S64b}}
}

// Multiplication : unsigned
void unsignMulEW_1(void) {
  (UINT_MAX / 2) * 3; // expected-warning{{Integer Overflow. Multiplication of 2147483647 U32b ((~0U) / 2) with 3 U32b}}
}
void unsignMulEW_2(void) {
  (ULONG_MAX / 2) * 3; // expected-warning{{Integer Overflow. Multiplication of 9223372036854775807 U64b ((~0UL) / 2) with 3 U64b}}
}

// New
void newEW_1(void) {
  // (INT_MAX / 2) * sizeof(int). Overflowed value is used in memory allocation.
  new int[INT_MAX / 2]; // expected-warning{{Integer Overflow. Multiplication of 4 U32b with 1073741823 S32b (((int)(~0U >> 1)) / 2) while memory allocation}}
}

// Test cases for GlobalsMembersHeuristics
namespace HT_1 {
void test_1(int b) {
  if (b == INT_MIN)
    b - 1; // no-warning
}
}

namespace HT_2 {
class C {
  int a;
  void foo() {
    if (a == INT_MIN)
      a - 1; // no-warning
  }
};
}

namespace HT_3 {
class C {
public:
  int a;
};
void foo() {
  C c;
  c.a = INT_MAX;
  c.a + 1; // no-warning
}
}

namespace HT_4 {
class C {
  int a;
  void foo() {
    a = INT_MAX;
    ((a - 1) + 1) + 1; // no-warning
  }
};
}

namespace HT_5 {
class C {
  int a;
  void foo() {
    a = -1;
    a + 1U; // no-warning
  }
};
}

void conjTest(const char *no_proxy) {
  unsigned a = 0;
  if (strchr(", ", no_proxy[0]))
    a++;
  // FIXME: shouldn't warn
  if (strchr(", ", no_proxy[0]))
    a - 1; // expected-warning{{Integer Underflow. Subtraction of 1 U32b from 0 U32b (a)}}
}
