#![feature(coverage_attribute)]
//@ edition: 2021
//@ compile-flags: -Zcoverage-options=mcdc
//@ llvm-cov-flags: --show-mcdc

// Tests MC/DC coverage for nested boolean expressions: (a && b) || c
// This tests more complex decision structures where conditions are nested.
// MC/DC requires showing that each condition independently affects the outcome.

use core::hint::black_box;

// Helper macro to prevent start-of-function spans from being merged
macro_rules! no_merge {
    () => {
        for _ in 0..1 {}
    };
}

fn nested_and_or(a: bool, b: bool, c: bool) -> bool {
    no_merge!();

    // MC/DC decision: (a && b) || c
    // This is a complex decision with three conditions
    // Test vectors for MC/DC coverage:
    // - Show 'a' independently affects outcome
    // - Show 'b' independently affects outcome
    // - Show 'c' independently affects outcome
    let result = (a && b) || c;
    black_box(result);
    result
}

fn nested_or_and(a: bool, b: bool, c: bool) -> bool {
    no_merge!();

    // MC/DC decision: (a || b) && c
    let result = (a || b) && c;
    black_box(result);
    result
}

fn deeply_nested(a: bool, b: bool, c: bool, d: bool) -> bool {
    no_merge!();

    // MC/DC decision: ((a && b) || c) && d
    let result = ((a && b) || c) && d;
    black_box(result);
    result
}

fn nested_in_if(a: bool, b: bool, c: bool) {
    no_merge!();

    // MC/DC decision in if condition
    if (a && b) || c {
        black_box("condition true");
    } else {
        black_box("condition false");
    }
}

#[coverage(off)]
fn main() {
    // Test (a && b) || c with various combinations
    // to achieve MC/DC coverage

    // Cases where c=false (testing a && b)
    assert!(!nested_and_or(false, false, false));
    assert!(!nested_and_or(false, true, false));
    assert!(!nested_and_or(true, false, false));
    assert!(nested_and_or(true, true, false));

    // Cases where c=true (short-circuits the OR)
    assert!(nested_and_or(false, false, true));
    assert!(nested_and_or(true, true, true));

    // Test (a || b) && c
    assert!(!nested_or_and(false, false, false));
    assert!(nested_or_and(false, true, true));
    assert!(nested_or_and(true, false, true));
    assert!(nested_or_and(true, true, true));
    assert!(!nested_or_and(true, true, false));

    // Test deeply nested expression
    assert!(!deeply_nested(false, false, false, false));
    assert!(deeply_nested(true, true, false, true));
    assert!(deeply_nested(false, false, true, true));
    assert!(!deeply_nested(true, true, true, false));

    // Test in if statement
    nested_in_if(false, false, false);
    nested_in_if(true, true, false);
    nested_in_if(false, false, true);
}
