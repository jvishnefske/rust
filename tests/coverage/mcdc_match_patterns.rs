#![feature(coverage_attribute)]
//@ edition: 2021
//@ compile-flags: -Zcoverage-options=mcdc
//@ llvm-cov-flags: --show-mcdc

// Tests MC/DC coverage for match expressions with refutable patterns.
// Per the arxiv paper (https://arxiv.org/html/2409.08708v1), refutable patterns
// should be treated as MC/DC decisions where directly refutable sub-patterns
// become conditions.

use core::hint::black_box;

// Helper macro to prevent start-of-function spans from being merged
macro_rules! no_merge {
    () => {
        for _ in 0..1 {}
    };
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Color {
    Red,
    Green,
    Blue,
}

#[derive(Debug, Clone, Copy)]
enum Shape {
    Circle(u32),
    Rectangle(u32, u32),
    Triangle,
}

// Test 1: Simple match with literal patterns (directly refutable)
fn match_literal(x: i32) {
    no_merge!();

    // Each literal pattern is a directly refutable condition
    match x {
        1 => { black_box(1); }
        2 => { black_box(2); }
        3 => { black_box(3); }
        _ => { black_box(0); }
    }
}

// Test 2: Match with range patterns (directly refutable)
fn match_range(x: i32) {
    no_merge!();

    // Range patterns are directly refutable conditions
    match x {
        0..=10 => { black_box(1); }
        11..=20 => { black_box(2); }
        21..=30 => { black_box(3); }
        _ => { black_box(0); }
    }
}

// Test 3: Match with enum variant patterns (directly refutable)
fn match_enum(color: Color) {
    no_merge!();

    // Each variant pattern is a directly refutable condition
    match color {
        Color::Red => { black_box(1); }
        Color::Green => { black_box(2); }
        Color::Blue => { black_box(3); }
    }
}

// Test 4: Match with guards (guards are additional conditions)
fn match_with_guard(x: i32) {
    no_merge!();

    // Pattern test + guard form a compound MC/DC decision
    match x {
        n if n < 0 => { black_box(n); }
        n if n > 0 => { black_box(n); }
        _ => { black_box(0); }
    }
}

// Test 5: Match with complex patterns (variant + destructuring)
fn match_complex(shape: Shape) -> u32 {
    no_merge!();

    // Variant pattern is directly refutable
    match shape {
        Shape::Circle(r) => black_box(r),
        Shape::Rectangle(w, h) => black_box(w * h),
        Shape::Triangle => black_box(0),
    }
}

// Test 6: Match with multiple patterns per arm (or-patterns)
fn match_or_pattern(x: i32) {
    no_merge!();

    // Or-patterns create OR decisions
    match x {
        1 | 2 | 3 => { black_box(1); }
        4 | 5 | 6 => { black_box(2); }
        _ => { black_box(0); }
    }
}

// Test 7: Match with guard and pattern destructuring
fn match_guard_destructure(shape: Shape) {
    no_merge!();

    // Variant pattern + guard condition
    match shape {
        Shape::Circle(r) if r > 10 => { black_box(r); }
        Shape::Circle(r) => { black_box(r); }
        Shape::Rectangle(w, h) if w == h => { black_box(w * h); }
        Shape::Rectangle(w, h) => { black_box(w + h); }
        Shape::Triangle => { black_box(0u32); }
    }
}

// Test 8: Match with slice patterns (directly refutable via length check)
fn match_slice(slice: &[i32]) {
    no_merge!();

    // Slice length is directly refutable
    match slice {
        [] => { black_box(0); }
        [x] => { black_box(*x); }
        [x, y] => { black_box(x + y); }
        _ => { black_box(-1); }
    }
}

// Test 9: Nested match expressions (each creates separate MC/DC decision)
fn match_nested(outer: Option<i32>) {
    no_merge!();

    match outer {
        Some(x) => {
            // Nested match creates a separate MC/DC decision
            match x {
                0..=10 => { black_box(1); }
                _ => { black_box(2); }
            }
        }
        None => { black_box(0); }
    }
}

// Test 10: Match with boolean pattern (if-style)
fn match_bool(cond: bool) {
    no_merge!();

    // Boolean constant patterns are directly refutable
    match cond {
        true => { black_box(1); }
        false => { black_box(0); }
    }
}

#[coverage(off)]
fn main() {
    // Test literal patterns - ensure all arms are covered
    match_literal(1);
    match_literal(2);
    match_literal(3);
    match_literal(99);

    // Test range patterns
    match_range(5);
    match_range(15);
    match_range(25);
    match_range(100);

    // Test enum patterns
    match_enum(Color::Red);
    match_enum(Color::Green);
    match_enum(Color::Blue);

    // Test guards - cover all outcomes
    match_with_guard(-5);
    match_with_guard(5);
    match_with_guard(0);

    // Test complex patterns
    match_complex(Shape::Circle(10));
    match_complex(Shape::Rectangle(4, 5));
    match_complex(Shape::Triangle);

    // Test or-patterns
    match_or_pattern(1);
    match_or_pattern(4);
    match_or_pattern(99);

    // Test guard + destructuring - all combinations
    match_guard_destructure(Shape::Circle(5));
    match_guard_destructure(Shape::Circle(15));
    match_guard_destructure(Shape::Rectangle(5, 5));
    match_guard_destructure(Shape::Rectangle(3, 4));
    match_guard_destructure(Shape::Triangle);

    // Test slice patterns
    match_slice(&[]);
    match_slice(&[1]);
    match_slice(&[1, 2]);
    match_slice(&[1, 2, 3]);

    // Test nested matches
    match_nested(Some(5));
    match_nested(Some(15));
    match_nested(None);

    // Test boolean patterns
    match_bool(true);
    match_bool(false);
}
