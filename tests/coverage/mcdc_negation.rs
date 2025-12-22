#![feature(coverage_attribute)]
//@ edition: 2021
//@ compile-flags: -Zcoverage-options=mcdc
//@ llvm-cov-flags: --show-mcdc

// Tests MC/DC coverage with negation operators.
// This validates the fix for LLVM issue #109952 where negated conditions
// were not properly handled in MC/DC coverage analysis.
//
// MC/DC must correctly track negated conditions (!a) as independent
// conditions that affect the decision outcome.

use core::hint::black_box;

// Helper macro to prevent start-of-function spans from being merged
macro_rules! no_merge {
    () => {
        for _ in 0..1 {}
    };
}

fn negation_and(a: bool, b: bool) -> bool {
    no_merge!();

    // MC/DC decision: !a && b
    // The negation of 'a' should be tracked as a condition
    // Test vectors:
    // - (true, false)  -> false  (!a is false)
    // - (true, true)   -> false  (!a is false)
    // - (false, false) -> false  (!a is true, b is false)
    // - (false, true)  -> true   (!a is true, b is true)
    let result = !a && b;
    black_box(result);
    result
}

fn negation_or(a: bool, b: bool) -> bool {
    no_merge!();

    // MC/DC decision: !a || b
    let result = !a || b;
    black_box(result);
    result
}

fn double_negation(a: bool, b: bool) -> bool {
    no_merge!();

    // MC/DC decision: !!a && b
    // Double negation should be handled correctly
    let result = !!a && b;
    black_box(result);
    result
}

fn negation_both(a: bool, b: bool) -> bool {
    no_merge!();

    // MC/DC decision: !a && !b
    let result = !a && !b;
    black_box(result);
    result
}

fn complex_negation(a: bool, b: bool, c: bool) -> bool {
    no_merge!();

    // MC/DC decision: (!a && b) || !c
    let result = (!a && b) || !c;
    black_box(result);
    result
}

fn negation_in_if(a: bool, b: bool) {
    no_merge!();

    if !a && b {
        black_box("negated a and b");
    } else {
        black_box("not (negated a and b)");
    }
}

#[coverage(off)]
fn main() {
    // Test !a && b
    assert!(!negation_and(true, false));
    assert!(!negation_and(true, true));
    assert!(!negation_and(false, false));
    assert!(negation_and(false, true));

    // Test !a || b
    assert!(negation_or(false, false));
    assert!(negation_or(false, true));
    assert!(!negation_or(true, false));
    assert!(negation_or(true, true));

    // Test !!a && b (double negation)
    assert!(!double_negation(false, false));
    assert!(!double_negation(false, true));
    assert!(!double_negation(true, false));
    assert!(double_negation(true, true));

    // Test !a && !b
    assert!(!negation_both(true, true));
    assert!(!negation_both(true, false));
    assert!(!negation_both(false, true));
    assert!(negation_both(false, false));

    // Test complex negation: (!a && b) || !c
    assert!(complex_negation(false, true, false));
    assert!(complex_negation(true, true, false));
    assert!(!complex_negation(true, false, true));
    assert!(complex_negation(false, true, true));

    // Test in if statement
    negation_in_if(true, true);
    negation_in_if(false, true);
    negation_in_if(false, false);
}
