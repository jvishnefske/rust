#![feature(coverage_attribute)]
//@ edition: 2021
//@ compile-flags: -Zcoverage-options=mcdc
//@ llvm-cov-flags: --show-mcdc

// Tests MC/DC coverage for if-let patterns.
// According to Rust's MC/DC implementation, refutable patterns are
// treated as MC/DC decisions. This test validates that if-let patterns
// are properly instrumented for MC/DC coverage.

use core::hint::black_box;

// Helper macro to prevent start-of-function spans from being merged
macro_rules! no_merge {
    () => {
        for _ in 0..1 {}
    };
}

fn if_let_option(value: Option<i32>) {
    no_merge!();

    // MC/DC decision: pattern match on Option
    if let Some(x) = value {
        black_box(x);
    } else {
        black_box(0);
    }
}

fn if_let_result(value: Result<i32, &str>) {
    no_merge!();

    // MC/DC decision: pattern match on Result
    if let Ok(x) = value {
        black_box(x);
    } else {
        black_box(-1);
    }
}

fn if_let_with_bool_guard(value: Option<i32>, guard: bool) {
    no_merge!();

    // MC/DC decision: pattern match followed by guard check
    // This tests the combination of pattern matching and boolean conditions
    if let Some(x) = value {
        if guard {
            black_box(x);
        } else {
            black_box(-x);
        }
    } else {
        black_box(0);
    }
}

fn if_let_enum(value: Color) {
    no_merge!();

    // MC/DC decision: pattern match on enum
    if let Color::Red = value {
        black_box(1);
    } else {
        black_box(0);
    }
}

fn nested_if_let(outer: Option<Option<i32>>) {
    no_merge!();

    // MC/DC decisions: nested pattern matches
    if let Some(inner) = outer {
        if let Some(x) = inner {
            black_box(x);
        } else {
            black_box(-1);
        }
    } else {
        black_box(-2);
    }
}

fn if_let_with_boolean_or(value: Option<i32>, fallback: bool) {
    no_merge!();

    // MC/DC decision with boolean OR
    // Pattern match OR boolean fallback
    let has_value = value.is_some() || fallback;
    if has_value {
        black_box(1);
    } else {
        black_box(0);
    }
}

#[derive(Debug, Clone, Copy)]
enum Color {
    Red,
    Green,
    Blue,
}

#[coverage(off)]
fn main() {
    // Test Option pattern matching
    if_let_option(Some(42));
    if_let_option(None);

    // Test Result pattern matching
    if_let_result(Ok(42));
    if_let_result(Err("error"));

    // Test pattern with guard - all combinations
    if_let_with_bool_guard(None, false);       // pattern fails, guard doesn't matter
    if_let_with_bool_guard(None, true);        // pattern fails, guard doesn't matter
    if_let_with_bool_guard(Some(10), false);   // pattern succeeds, guard fails
    if_let_with_bool_guard(Some(10), true);    // both succeed

    // Test enum pattern matching
    if_let_enum(Color::Red);
    if_let_enum(Color::Green);
    if_let_enum(Color::Blue);

    // Test nested if-let
    nested_if_let(None);
    nested_if_let(Some(None));
    nested_if_let(Some(Some(42)));

    // Test if-let with boolean OR
    if_let_with_boolean_or(Some(42), false);
    if_let_with_boolean_or(None, true);
    if_let_with_boolean_or(None, false);
}
