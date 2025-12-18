use std::assert_matches::assert_matches;
use std::collections::hash_map::Entry;

use rustc_data_structures::fx::FxHashMap;
use rustc_middle::mir::coverage::{
    BlockMarkerId, BranchSpan, ConditionId, ConditionIdOrDecisionOutcome, CoverageInfoHi,
    CoverageKind, DecisionId, MCDCConditionInfo, MCDCConditionSpan, MCDCDecisionInfo,
    MCDCDecisionSpan,
};
use rustc_middle::mir::{self, BasicBlock, SourceInfo, UnOp};
use rustc_middle::thir::{ExprId, ExprKind, LogicalOp, Pat, Thir};
use rustc_middle::ty::TyCtxt;
use rustc_span::def_id::LocalDefId;
use rustc_span::Span;

use crate::builder::{Builder, CFG};

/// Collects coverage-related information during MIR building, to eventually be
/// turned into a function's [`CoverageInfoHi`] when MIR building is complete.
pub(crate) struct CoverageInfoBuilder {
    /// Maps condition expressions to their enclosing `!`, for better instrumentation.
    nots: FxHashMap<ExprId, NotInfo>,

    markers: BlockMarkerGen,

    /// Present if branch coverage is enabled.
    branch_info: Option<BranchInfo>,

    /// Present if MC/DC coverage is enabled.
    mcdc_info: Option<MCDCInfo>,
}

#[derive(Default)]
struct BranchInfo {
    branch_spans: Vec<BranchSpan>,
}

/// MC/DC coverage collection state.
#[derive(Default)]
struct MCDCInfo {
    /// Completed MC/DC decision spans.
    decision_spans: Vec<MCDCDecisionSpan>,
    /// Completed MC/DC condition spans.
    condition_spans: Vec<MCDCConditionSpan>,
    /// The decision currently being built (if any).
    current_decision: Option<DecisionBuilder>,
    /// Counter for allocating decision IDs.
    next_decision_id: u32,
    /// Counter for allocating bitmap indices.
    next_bitmap_idx: u32,
}

/// Builder for constructing an MC/DC decision during THIR lowering.
struct DecisionBuilder {
    id: DecisionId,
    span: Span,
    /// Conditions collected so far for this decision.
    conditions: Vec<MCDCConditionInfo>,
    /// Condition spans collected so far.
    condition_spans: Vec<MCDCConditionSpan>,
    /// Counter for allocating condition IDs within this decision.
    next_condition_id: u32,
    /// Stack tracking the "next condition if false" for AND chains.
    /// Stack tracking the "next condition if true" for OR chains.
    condition_stack: Vec<ConditionStackEntry>,
}

/// Entry in the condition stack for tracking decision graph edges.
struct ConditionStackEntry {
    /// The logical operator at this level.
    op: LogicalOp,
    /// The condition ID that should be the "next" for the appropriate branch.
    condition_id: ConditionId,
}

#[derive(Clone, Copy)]
struct NotInfo {
    /// When visiting the associated expression as a branch condition, treat this
    /// enclosing `!` as the branch condition instead.
    enclosing_not: ExprId,
    /// True if the associated expression is nested within an odd number of `!`
    /// expressions relative to `enclosing_not` (inclusive of `enclosing_not`).
    is_flipped: bool,
}

#[derive(Default)]
struct BlockMarkerGen {
    num_block_markers: usize,
}

impl BlockMarkerGen {
    fn next_block_marker_id(&mut self) -> BlockMarkerId {
        let id = BlockMarkerId::from_usize(self.num_block_markers);
        self.num_block_markers += 1;
        id
    }

    fn inject_block_marker(
        &mut self,
        cfg: &mut CFG<'_>,
        source_info: SourceInfo,
        block: BasicBlock,
    ) -> BlockMarkerId {
        let id = self.next_block_marker_id();
        let marker_statement = mir::Statement::new(
            source_info,
            mir::StatementKind::Coverage(CoverageKind::BlockMarker { id }),
        );
        cfg.push(block, marker_statement);

        id
    }
}

impl CoverageInfoBuilder {
    /// Creates a new coverage info builder, but only if coverage instrumentation
    /// is enabled and `def_id` represents a function that is eligible for coverage.
    pub(crate) fn new_if_enabled(tcx: TyCtxt<'_>, def_id: LocalDefId) -> Option<Self> {
        if !tcx.sess.instrument_coverage() || !tcx.is_eligible_for_coverage(def_id) {
            return None;
        }

        Some(Self {
            nots: FxHashMap::default(),
            markers: BlockMarkerGen::default(),
            branch_info: tcx.sess.instrument_coverage_branch().then(BranchInfo::default),
            mcdc_info: tcx.sess.instrument_coverage_mcdc().then(MCDCInfo::default),
        })
    }

    /// Unary `!` expressions inside an `if` condition are lowered by lowering
    /// their argument instead, and then reversing the then/else arms of that `if`.
    ///
    /// That's awkward for branch coverage instrumentation, so to work around that
    /// we pre-emptively visit any affected `!` expressions, and record extra
    /// information that [`Builder::visit_coverage_branch_condition`] can use to
    /// synthesize branch instrumentation for the enclosing `!`.
    pub(crate) fn visit_unary_not(&mut self, thir: &Thir<'_>, unary_not: ExprId) {
        assert_matches!(thir[unary_not].kind, ExprKind::Unary { op: UnOp::Not, .. });

        // The information collected by this visitor is only needed when branch
        // coverage or higher is enabled.
        if self.branch_info.is_none() {
            return;
        }

        self.visit_with_not_info(
            thir,
            unary_not,
            // Set `is_flipped: false` for the `!` itself, so that its enclosed
            // expression will have `is_flipped: true`.
            NotInfo { enclosing_not: unary_not, is_flipped: false },
        );
    }

    fn visit_with_not_info(&mut self, thir: &Thir<'_>, expr_id: ExprId, not_info: NotInfo) {
        match self.nots.entry(expr_id) {
            // This expression has already been marked by an enclosing `!`.
            Entry::Occupied(_) => return,
            Entry::Vacant(entry) => entry.insert(not_info),
        };

        match thir[expr_id].kind {
            ExprKind::Unary { op: UnOp::Not, arg } => {
                // Invert the `is_flipped` flag for the contents of this `!`.
                let not_info = NotInfo { is_flipped: !not_info.is_flipped, ..not_info };
                self.visit_with_not_info(thir, arg, not_info);
            }
            ExprKind::Scope { value, .. } => self.visit_with_not_info(thir, value, not_info),
            ExprKind::Use { source } => self.visit_with_not_info(thir, source, not_info),
            // All other expressions (including `&&` and `||`) don't need any
            // special handling of their contents, so stop visiting.
            _ => {}
        }
    }

    fn register_two_way_branch<'tcx>(
        &mut self,
        cfg: &mut CFG<'tcx>,
        source_info: SourceInfo,
        true_block: BasicBlock,
        false_block: BasicBlock,
    ) {
        // Bail out if branch coverage is not enabled.
        let Some(branch_info) = self.branch_info.as_mut() else { return };

        let true_marker = self.markers.inject_block_marker(cfg, source_info, true_block);
        let false_marker = self.markers.inject_block_marker(cfg, source_info, false_block);

        branch_info.branch_spans.push(BranchSpan {
            span: source_info.span,
            true_marker,
            false_marker,
        });
    }

    pub(crate) fn into_done(self) -> Box<CoverageInfoHi> {
        let Self {
            nots: _,
            markers: BlockMarkerGen { num_block_markers },
            branch_info,
            mcdc_info,
        } = self;

        let branch_spans =
            branch_info.map(|branch_info| branch_info.branch_spans).unwrap_or_default();

        let (mcdc_decision_spans, mcdc_condition_spans) = mcdc_info
            .map(|info| (info.decision_spans, info.condition_spans))
            .unwrap_or_default();

        // For simplicity, always return an info struct (without Option), even
        // if there's nothing interesting in it.
        Box::new(CoverageInfoHi {
            num_block_markers,
            branch_spans,
            mcdc_decision_spans,
            mcdc_condition_spans,
        })
    }

    pub(crate) fn as_done(&self) -> Box<CoverageInfoHi> {
        let &Self {
            nots: _,
            markers: BlockMarkerGen { num_block_markers },
            ref branch_info,
            ref mcdc_info,
        } = self;

        let branch_spans = branch_info
            .as_ref()
            .map(|branch_info| branch_info.branch_spans.as_slice())
            .unwrap_or_default()
            .to_owned();

        let (mcdc_decision_spans, mcdc_condition_spans) = mcdc_info
            .as_ref()
            .map(|info| (info.decision_spans.clone(), info.condition_spans.clone()))
            .unwrap_or_default();

        // For simplicity, always return an info struct (without Option), even
        // if there's nothing interesting in it.
        Box::new(CoverageInfoHi {
            num_block_markers,
            branch_spans,
            mcdc_decision_spans,
            mcdc_condition_spans,
        })
    }

    /// Starts a new MC/DC decision. Returns the decision ID if MC/DC is enabled.
    ///
    /// Call this when entering a top-level boolean expression (e.g., condition of `if`).
    pub(crate) fn mcdc_enter_decision(&mut self, span: Span) -> Option<DecisionId> {
        let mcdc_info = self.mcdc_info.as_mut()?;

        // If there's already an active decision, we're in a nested expression.
        // LLVM doesn't support nested decisions, so we skip this one.
        if mcdc_info.current_decision.is_some() {
            return None;
        }

        let id = DecisionId::from_u32(mcdc_info.next_decision_id);
        mcdc_info.next_decision_id += 1;

        mcdc_info.current_decision = Some(DecisionBuilder {
            id,
            span,
            conditions: Vec::new(),
            condition_spans: Vec::new(),
            next_condition_id: 0,
            condition_stack: Vec::new(),
        });

        Some(id)
    }

    /// Records a condition within the current MC/DC decision.
    ///
    /// Returns the condition ID if MC/DC is enabled and there's an active decision.
    /// The `is_negated` flag indicates if the condition is wrapped in an odd number
    /// of `!` operators (used to fix LLVM #109952).
    pub(crate) fn mcdc_record_condition<'tcx>(
        &mut self,
        cfg: &mut CFG<'tcx>,
        source_info: SourceInfo,
        true_block: BasicBlock,
        false_block: BasicBlock,
        is_negated: bool,
    ) -> Option<ConditionId> {
        let mcdc_info = self.mcdc_info.as_mut()?;
        let decision = mcdc_info.current_decision.as_mut()?;

        // LLVM limits decisions to 6 conditions due to exponential bitmap growth
        if decision.next_condition_id >= 6 {
            return None;
        }

        let condition_id = ConditionId::from_u32(decision.next_condition_id);
        decision.next_condition_id += 1;

        // Determine true_next and false_next based on the condition stack.
        // These will be updated when we encounter the next condition or when
        // the decision is finalized.
        let (true_next, false_next) = self.compute_condition_edges(condition_id);

        // Inject block markers for the true and false paths
        let true_marker = self.markers.inject_block_marker(cfg, source_info, true_block);
        let false_marker = self.markers.inject_block_marker(cfg, source_info, false_block);

        let mcdc_info = self.mcdc_info.as_mut().unwrap();
        let decision = mcdc_info.current_decision.as_mut().unwrap();

        decision.conditions.push(MCDCConditionInfo {
            id: condition_id,
            is_negated,
            true_next,
            false_next,
        });

        decision.condition_spans.push(MCDCConditionSpan {
            span: source_info.span,
            decision_id: decision.id,
            condition_id,
            true_marker,
            false_marker,
        });

        Some(condition_id)
    }

    /// Computes the true_next and false_next edges for a new condition
    /// based on the current condition stack.
    fn compute_condition_edges(
        &self,
        _condition_id: ConditionId,
    ) -> (ConditionIdOrDecisionOutcome, ConditionIdOrDecisionOutcome) {
        let mcdc_info = match &self.mcdc_info {
            Some(info) => info,
            None => return (None, None),
        };
        let decision = match &mcdc_info.current_decision {
            Some(d) => d,
            None => return (None, None),
        };

        // Walk the stack to determine edges.
        // For `&&`: false -> short-circuit to decision false, true -> continue
        // For `||`: true -> short-circuit to decision true, false -> continue
        let mut true_next: ConditionIdOrDecisionOutcome = None; // Decision true by default
        let mut false_next: ConditionIdOrDecisionOutcome = None; // Decision false by default

        for entry in decision.condition_stack.iter().rev() {
            match entry.op {
                LogicalOp::And => {
                    // In AND: if we're false, we go to the "next" from the stack
                    // (which represents where to go on short-circuit)
                    if false_next.is_none() {
                        false_next = Some(entry.condition_id);
                    }
                }
                LogicalOp::Or => {
                    // In OR: if we're true, we go to the "next" from the stack
                    if true_next.is_none() {
                        true_next = Some(entry.condition_id);
                    }
                }
            }
        }

        (true_next, false_next)
    }

    /// Pushes a logical operator context for MC/DC decision graph construction.
    ///
    /// Call this before processing the RHS of a logical operation.
    pub(crate) fn mcdc_push_logical_op(&mut self, op: LogicalOp, condition_id: ConditionId) {
        let Some(mcdc_info) = self.mcdc_info.as_mut() else { return };
        let Some(decision) = mcdc_info.current_decision.as_mut() else { return };

        decision.condition_stack.push(ConditionStackEntry { op, condition_id });
    }

    /// Pops a logical operator context after processing the RHS.
    pub(crate) fn mcdc_pop_logical_op(&mut self) {
        let Some(mcdc_info) = self.mcdc_info.as_mut() else { return };
        let Some(decision) = mcdc_info.current_decision.as_mut() else { return };

        decision.condition_stack.pop();
    }

    /// Finalizes the current MC/DC decision.
    ///
    /// Updates condition edges based on final structure and moves the decision
    /// to the completed list.
    pub(crate) fn mcdc_exit_decision(&mut self, decision_id: DecisionId) {
        let Some(mcdc_info) = self.mcdc_info.as_mut() else { return };

        let Some(mut decision) = mcdc_info.current_decision.take() else { return };

        // Verify we're exiting the right decision
        if decision.id != decision_id {
            // Put it back and bail - something went wrong
            mcdc_info.current_decision = Some(decision);
            return;
        }

        let num_conditions = decision.conditions.len() as u16;

        // Skip decisions with fewer than 2 conditions (no independence to measure)
        if num_conditions < 2 {
            return;
        }

        // Finalize condition edges: update conditions to point to the next condition
        // when they would otherwise continue evaluation.
        finalize_condition_edges(&mut decision);

        // Allocate bitmap space for this decision.
        // Each decision needs 2^n bits for n conditions (one bit per test vector).
        let bitmap_idx = mcdc_info.next_bitmap_idx;
        let num_test_vectors = 1u32 << num_conditions;
        // Round up to bytes
        let bitmap_bytes = (num_test_vectors + 7) / 8;
        mcdc_info.next_bitmap_idx += bitmap_bytes;

        let decision_info = MCDCDecisionInfo {
            id: decision.id,
            bitmap_idx,
            num_conditions,
        };

        // Move condition spans to the global list
        mcdc_info.condition_spans.extend(decision.condition_spans);

        // Create the decision span
        mcdc_info.decision_spans.push(MCDCDecisionSpan {
            span: decision.span,
            decision_info,
            conditions: decision.conditions,
        });
    }

    /// Returns true if we're currently inside an MC/DC decision.
    pub(crate) fn is_in_mcdc_decision(&self) -> bool {
        self.mcdc_info
            .as_ref()
            .is_some_and(|info| info.current_decision.is_some())
    }
}

/// Updates condition edges to create a proper decision graph.
fn finalize_condition_edges(decision: &mut DecisionBuilder) {
    // For a linear chain like `a && b && c`:
    // - Condition 0 (a): true -> Condition 1, false -> decision false
    // - Condition 1 (b): true -> Condition 2, false -> decision false
    // - Condition 2 (c): true -> decision true, false -> decision false
    //
    // For `a || b || c`:
    // - Condition 0 (a): true -> decision true, false -> Condition 1
    // - Condition 1 (b): true -> decision true, false -> Condition 2
    // - Condition 2 (c): true -> decision true, false -> decision false
    //
    // The edges were computed during construction based on the stack state,
    // but we may need to update forward references.

    let num_conditions = decision.conditions.len();
    if num_conditions == 0 {
        return;
    }

    // For conditions that point to "continue" (represented as pointing to
    // themselves or having None), update them to point to the next condition
    // or decision outcome.
    for i in 0..num_conditions {
        let next_condition = if i + 1 < num_conditions {
            Some(ConditionId::from_usize(i + 1))
        } else {
            None // Last condition - points to decision outcome
        };

        let condition = &mut decision.conditions[i];

        // If true_next is None (decision true outcome), check if we should
        // instead point to the next condition. This depends on the operator context.
        // For now, we leave the edges as computed during construction.
        // The stack-based computation should have set correct edges.

        // However, for the last condition in a chain, we ensure the
        // "continue" path points to decision outcome (None).
        if condition.true_next == Some(condition.id) {
            condition.true_next = next_condition;
        }
        if condition.false_next == Some(condition.id) {
            condition.false_next = next_condition;
        }
    }
}

impl<'tcx> Builder<'_, 'tcx> {
    /// If condition coverage is enabled, inject extra blocks and marker statements
    /// that will let us track the value of the condition in `place`.
    pub(crate) fn visit_coverage_standalone_condition(
        &mut self,
        mut expr_id: ExprId,     // Expression giving the span of the condition
        place: mir::Place<'tcx>, // Already holds the boolean condition value
        block: &mut BasicBlock,
    ) {
        // Bail out if condition coverage is not enabled for this function.
        let Some(coverage_info) = self.coverage_info.as_mut() else { return };
        if !self.tcx.sess.instrument_coverage_condition() {
            return;
        };

        // Remove any wrappers, so that we can inspect the real underlying expression.
        while let ExprKind::Use { source: inner } | ExprKind::Scope { value: inner, .. } =
            self.thir[expr_id].kind
        {
            expr_id = inner;
        }
        // If the expression is a lazy logical op, it will naturally get branch
        // coverage as part of its normal lowering, so we can disregard it here.
        if let ExprKind::LogicalOp { .. } = self.thir[expr_id].kind {
            return;
        }

        let source_info = SourceInfo { span: self.thir[expr_id].span, scope: self.source_scope };

        // Using the boolean value that has already been stored in `place`, set up
        // control flow in the shape of a diamond, so that we can place separate
        // marker statements in the true and false blocks. The coverage MIR pass
        // will use those markers to inject coverage counters as appropriate.
        //
        //          block
        //         /     \
        // true_block   false_block
        //  (marker)     (marker)
        //         \     /
        //        join_block

        let true_block = self.cfg.start_new_block();
        let false_block = self.cfg.start_new_block();
        self.cfg.terminate(
            *block,
            source_info,
            mir::TerminatorKind::if_(mir::Operand::Copy(place), true_block, false_block),
        );

        coverage_info.register_two_way_branch(&mut self.cfg, source_info, true_block, false_block);

        let join_block = self.cfg.start_new_block();
        self.cfg.goto(true_block, source_info, join_block);
        self.cfg.goto(false_block, source_info, join_block);
        // Any subsequent codegen in the caller should use the new join block.
        *block = join_block;
    }

    /// If branch coverage is enabled, inject marker statements into `then_block`
    /// and `else_block`, and record their IDs in the table of branch spans.
    pub(crate) fn visit_coverage_branch_condition(
        &mut self,
        mut expr_id: ExprId,
        mut then_block: BasicBlock,
        mut else_block: BasicBlock,
    ) {
        // Bail out if coverage is not enabled for this function.
        let Some(coverage_info) = self.coverage_info.as_mut() else { return };

        // If this condition expression is nested within one or more `!` expressions,
        // replace it with the enclosing `!` collected by `visit_unary_not`.
        if let Some(&NotInfo { enclosing_not, is_flipped }) = coverage_info.nots.get(&expr_id) {
            expr_id = enclosing_not;
            if is_flipped {
                std::mem::swap(&mut then_block, &mut else_block);
            }
        }

        let source_info = SourceInfo { span: self.thir[expr_id].span, scope: self.source_scope };

        coverage_info.register_two_way_branch(&mut self.cfg, source_info, then_block, else_block);
    }

    /// If branch coverage is enabled, inject marker statements into `true_block`
    /// and `false_block`, and record their IDs in the table of branches.
    ///
    /// Used to instrument let-else and if-let (including let-chains) for branch coverage.
    pub(crate) fn visit_coverage_conditional_let(
        &mut self,
        pattern: &Pat<'tcx>, // Pattern that has been matched when the true path is taken
        true_block: BasicBlock,
        false_block: BasicBlock,
    ) {
        // Bail out if coverage is not enabled for this function.
        let Some(coverage_info) = self.coverage_info.as_mut() else { return };

        let source_info = SourceInfo { span: pattern.span, scope: self.source_scope };
        coverage_info.register_two_way_branch(&mut self.cfg, source_info, true_block, false_block);
    }

    /// If MC/DC coverage is enabled, record this atomic condition within the current decision.
    ///
    /// This method records the condition and updates `last_mcdc_condition_id` so that
    /// subsequent logical operators can properly link conditions in the decision graph.
    pub(crate) fn visit_mcdc_condition(
        &mut self,
        expr_id: ExprId,
        then_block: BasicBlock,
        else_block: BasicBlock,
    ) {
        // Bail out if MC/DC is not enabled or there's no active decision.
        let Some(coverage_info) = self.coverage_info.as_mut() else { return };
        if !coverage_info.is_in_mcdc_decision() {
            return;
        }

        let source_info = SourceInfo { span: self.thir[expr_id].span, scope: self.source_scope };

        // Check if this condition is negated (wrapped in `!` operators).
        // This implements the fix for LLVM #109952.
        let is_negated = coverage_info
            .nots
            .get(&expr_id)
            .is_some_and(|not_info| not_info.is_flipped);

        // Record the condition and get its ID.
        let condition_id = coverage_info.mcdc_record_condition(
            &mut self.cfg,
            source_info,
            then_block,
            else_block,
            is_negated,
        );

        // Store the condition ID for use by logical operators when building
        // the decision graph edges.
        self.last_mcdc_condition_id = condition_id;
    }

    /// Starts an MC/DC decision. Call this at the entry point of a top-level
    /// boolean expression (e.g., the condition of an `if` statement).
    ///
    /// Returns the decision ID if MC/DC is enabled, or None otherwise.
    pub(crate) fn mcdc_enter_decision(&mut self, span: rustc_span::Span) -> Option<DecisionId> {
        let coverage_info = self.coverage_info.as_mut()?;
        self.last_mcdc_condition_id = None;
        coverage_info.mcdc_enter_decision(span)
    }

    /// Finalizes an MC/DC decision. Call this after the boolean expression
    /// has been fully lowered.
    pub(crate) fn mcdc_exit_decision(&mut self, decision_id: DecisionId) {
        if let Some(coverage_info) = self.coverage_info.as_mut() {
            coverage_info.mcdc_exit_decision(decision_id);
        }
        self.last_mcdc_condition_id = None;
    }
}
