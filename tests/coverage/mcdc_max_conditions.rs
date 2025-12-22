#![feature(coverage_attribute)]
//@ edition: 2021
//@ compile-flags: -Zcoverage-options=mcdc
//@ llvm-cov-flags: --show-mcdc

// Tests MC/DC coverage with the maximum number of conditions.
// LLVM's MC/DC implementation has a limit of 6 conditions per decision.
// This test validates that the compiler correctly handles decisions
// at this limit and potentially warns about exceeding it.

use core::hint::black_box;

// Helper macro to prevent start-of-function spans from being merged
macro_rules! no_merge {
    () => {
        for _ in 0..1 {}
    };
}

fn six_conditions_and(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> bool {
    no_merge!();

    // MC/DC decision with 6 conditions (LLVM limit)
    // This is at the maximum supported by LLVM's MC/DC implementation
    let result = a && b && c && d && e && f;
    black_box(result);
    result
}

fn six_conditions_or(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> bool {
    no_merge!();

    // MC/DC decision with 6 conditions using OR
    let result = a || b || c || d || e || f;
    black_box(result);
    result
}

fn six_conditions_mixed(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> bool {
    no_merge!();

    // MC/DC decision with 6 conditions, mixed operators
    // (a && b) || (c && d) || (e && f)
    let result = (a && b) || (c && d) || (e && f);
    black_box(result);
    result
}

fn six_conditions_complex(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> bool {
    no_merge!();

    // More complex nesting with 6 conditions
    // ((a || b) && c) || ((d || e) && f)
    let result = ((a || b) && c) || ((d || e) && f);
    black_box(result);
    result
}

fn five_conditions(a: bool, b: bool, c: bool, d: bool, e: bool) -> bool {
    no_merge!();

    // MC/DC decision with 5 conditions (under the limit)
    let result = a && b && c && d && e;
    black_box(result);
    result
}

#[coverage(off)]
fn main() {
    // Test 6-condition AND
    // For full MC/DC coverage, we need to show each condition
    // independently affects the outcome
    assert!(!six_conditions_and(false, true, true, true, true, true));
    assert!(!six_conditions_and(true, false, true, true, true, true));
    assert!(!six_conditions_and(true, true, false, true, true, true));
    assert!(!six_conditions_and(true, true, true, false, true, true));
    assert!(!six_conditions_and(true, true, true, true, false, true));
    assert!(!six_conditions_and(true, true, true, true, true, false));
    assert!(six_conditions_and(true, true, true, true, true, true));
    assert!(!six_conditions_and(false, false, false, false, false, false));

    // Test 6-condition OR
    assert!(six_conditions_or(true, false, false, false, false, false));
    assert!(six_conditions_or(false, true, false, false, false, false));
    assert!(six_conditions_or(false, false, true, false, false, false));
    assert!(six_conditions_or(false, false, false, true, false, false));
    assert!(six_conditions_or(false, false, false, false, true, false));
    assert!(six_conditions_or(false, false, false, false, false, true));
    assert!(!six_conditions_or(false, false, false, false, false, false));
    assert!(six_conditions_or(true, true, true, true, true, true));

    // Test 6-condition mixed: (a && b) || (c && d) || (e && f)
    assert!(six_conditions_mixed(true, true, false, false, false, false));
    assert!(six_conditions_mixed(false, false, true, true, false, false));
    assert!(six_conditions_mixed(false, false, false, false, true, true));
    assert!(!six_conditions_mixed(true, false, false, false, false, false));
    assert!(!six_conditions_mixed(false, false, false, false, false, false));

    // Test 6-condition complex: ((a || b) && c) || ((d || e) && f)
    assert!(six_conditions_complex(true, false, true, false, false, false));
    assert!(six_conditions_complex(false, true, true, false, false, false));
    assert!(six_conditions_complex(false, false, false, true, false, true));
    assert!(six_conditions_complex(false, false, false, false, true, true));
    assert!(!six_conditions_complex(true, false, false, false, false, false));
    assert!(!six_conditions_complex(false, false, false, false, false, false));

    // Test 5-condition (under the limit)
    assert!(!five_conditions(false, true, true, true, true));
    assert!(!five_conditions(true, false, true, true, true));
    assert!(!five_conditions(true, true, false, true, true));
    assert!(!five_conditions(true, true, true, false, true));
    assert!(!five_conditions(true, true, true, true, false));
    assert!(five_conditions(true, true, true, true, true));
}
