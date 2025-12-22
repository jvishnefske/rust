#![feature(coverage_attribute)]
//@ edition: 2021
//@ compile-flags: -Zcoverage-options=mcdc
//@ llvm-cov-flags: --show-mcdc

// Tests MC/DC coverage for the simple AND operator (a && b).
// MC/DC requires each condition to independently affect the outcome.
// For (a && b), we need test cases where:
// - a changes the outcome while b is held constant
// - b changes the outcome while a is held constant

use core::hint::black_box;

// Helper macro to prevent start-of-function spans from being merged
macro_rules! no_merge {
    () => {
        for _ in 0..1 {}
    };
}

fn simple_and(a: bool, b: bool) -> bool {
    no_merge!();

    // MC/DC decision: a && b
    // Test vectors needed for full MC/DC coverage:
    // 1. (false, false) -> false
    // 2. (false, true)  -> false  (a independently affects outcome)
    // 3. (true, false)  -> false  (b independently affects outcome)
    // 4. (true, true)   -> true
    let result = a && b;
    black_box(result);
    result
}

fn simple_and_in_if(a: bool, b: bool) {
    no_merge!();

    // MC/DC decision in if condition
    if a && b {
        black_box("both true");
    } else {
        black_box("not both true");
    }
}

fn simple_and_return(a: bool, b: bool) -> bool {
    no_merge!();

    // MC/DC decision in return expression
    a && b
}

#[coverage(off)]
fn main() {
    // Exercise all combinations for MC/DC coverage
    // Each combination is tested to ensure full MC/DC coverage

    // Test case 1: (false, false) -> false
    assert!(!simple_and(false, false));
    simple_and_in_if(false, false);
    assert!(!simple_and_return(false, false));

    // Test case 2: (false, true) -> false
    // This shows 'a' independently affects the outcome
    assert!(!simple_and(false, true));
    simple_and_in_if(false, true);
    assert!(!simple_and_return(false, true));

    // Test case 3: (true, false) -> false
    // This shows 'b' independently affects the outcome
    assert!(!simple_and(true, false));
    simple_and_in_if(true, false);
    assert!(!simple_and_return(true, false));

    // Test case 4: (true, true) -> true
    assert!(simple_and(true, true));
    simple_and_in_if(true, true);
    assert!(simple_and_return(true, true));
}
