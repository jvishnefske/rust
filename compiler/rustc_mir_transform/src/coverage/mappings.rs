use rustc_index::IndexVec;
use rustc_middle::mir::coverage::{
    BlockMarkerId, BranchSpan, CoverageInfoHi, CoverageKind, Mapping, MappingKind,
    MCDCConditionSpan, MCDCDecisionSpan,
};
use rustc_middle::mir::{self, BasicBlock, StatementKind};
use rustc_middle::ty::TyCtxt;
use rustc_span::ExpnKind;

use crate::coverage::expansion::{self, ExpnTree};
use crate::coverage::graph::CoverageGraph;
use crate::coverage::hir_info::ExtractedHirInfo;
use crate::coverage::spans::extract_refined_covspans;

#[derive(Default)]
pub(crate) struct ExtractedMappings {
    pub(crate) mappings: Vec<Mapping>,
}

/// Extracts coverage-relevant spans from MIR, and uses them to create
/// coverage mapping data for inclusion in MIR.
pub(crate) fn extract_mappings_from_mir<'tcx>(
    tcx: TyCtxt<'tcx>,
    mir_body: &mir::Body<'tcx>,
    hir_info: &ExtractedHirInfo,
    graph: &CoverageGraph,
) -> ExtractedMappings {
    let expn_tree = expansion::build_expn_tree(mir_body, hir_info, graph);

    let mut mappings = vec![];

    // Extract ordinary code mappings from MIR statement/terminator spans.
    extract_refined_covspans(tcx, hir_info, graph, &expn_tree, &mut mappings);

    extract_branch_mappings(mir_body, hir_info, graph, &expn_tree, &mut mappings);

    // Extract MC/DC mappings if enabled.
    if tcx.sess.instrument_coverage_mcdc() {
        extract_mcdc_mappings(mir_body, hir_info, graph, &expn_tree, &mut mappings);
    }

    ExtractedMappings { mappings }
}

fn resolve_block_markers(
    coverage_info_hi: &CoverageInfoHi,
    mir_body: &mir::Body<'_>,
) -> IndexVec<BlockMarkerId, Option<BasicBlock>> {
    let mut block_markers = IndexVec::<BlockMarkerId, Option<BasicBlock>>::from_elem_n(
        None,
        coverage_info_hi.num_block_markers,
    );

    // Fill out the mapping from block marker IDs to their enclosing blocks.
    for (bb, data) in mir_body.basic_blocks.iter_enumerated() {
        for statement in &data.statements {
            if let StatementKind::Coverage(CoverageKind::BlockMarker { id }) = statement.kind {
                block_markers[id] = Some(bb);
            }
        }
    }

    block_markers
}

fn extract_branch_mappings(
    mir_body: &mir::Body<'_>,
    hir_info: &ExtractedHirInfo,
    graph: &CoverageGraph,
    expn_tree: &ExpnTree,
    mappings: &mut Vec<Mapping>,
) {
    let Some(coverage_info_hi) = mir_body.coverage_info_hi.as_deref() else { return };
    let block_markers = resolve_block_markers(coverage_info_hi, mir_body);

    // For now, ignore any branch span that was introduced by
    // expansion. This makes things like assert macros less noisy.
    let Some(node) = expn_tree.get(hir_info.body_span.ctxt().outer_expn()) else { return };
    if node.expn_kind != ExpnKind::Root {
        return;
    }

    mappings.extend(node.branch_spans.iter().filter_map(
        |&BranchSpan { span, true_marker, false_marker }| try {
            let bcb_from_marker = |marker: BlockMarkerId| graph.bcb_from_bb(block_markers[marker]?);

            let true_bcb = bcb_from_marker(true_marker)?;
            let false_bcb = bcb_from_marker(false_marker)?;

            Mapping { span, kind: MappingKind::Branch { true_bcb, false_bcb } }
        },
    ));
}

/// Extracts MC/DC decision and branch mappings from `CoverageInfoHi`.
fn extract_mcdc_mappings(
    mir_body: &mir::Body<'_>,
    hir_info: &ExtractedHirInfo,
    graph: &CoverageGraph,
    expn_tree: &ExpnTree,
    mappings: &mut Vec<Mapping>,
) {
    let Some(coverage_info_hi) = mir_body.coverage_info_hi.as_deref() else { return };
    let block_markers = resolve_block_markers(coverage_info_hi, mir_body);

    // For now, ignore any MC/DC spans that were introduced by expansion.
    let Some(node) = expn_tree.get(hir_info.body_span.ctxt().outer_expn()) else { return };
    if node.expn_kind != ExpnKind::Root {
        return;
    }

    // Extract MC/DC decision mappings.
    for decision_span in &coverage_info_hi.mcdc_decision_spans {
        let MCDCDecisionSpan { span, decision_info, conditions: _ } = decision_span;

        mappings.push(Mapping {
            span: *span,
            kind: MappingKind::MCDCDecision {
                decision_id: decision_info.id,
                bitmap_idx: decision_info.bitmap_idx,
                num_conditions: decision_info.num_conditions,
            },
        });
    }

    // Extract MC/DC branch mappings (conditions).
    for condition_span in &coverage_info_hi.mcdc_condition_spans {
        let MCDCConditionSpan {
            span,
            decision_id: _,
            condition_id,
            true_marker,
            false_marker,
        } = condition_span;

        let bcb_from_marker = |marker: BlockMarkerId| -> Option<_> {
            graph.bcb_from_bb(block_markers[marker]?)
        };

        let Some(true_bcb) = bcb_from_marker(*true_marker) else { continue };
        let Some(false_bcb) = bcb_from_marker(*false_marker) else { continue };

        // Find the decision this condition belongs to so we can get the edge info.
        let decision = coverage_info_hi.mcdc_decision_spans.iter().find(|d| {
            d.conditions.iter().any(|c| c.id == *condition_id)
        });

        let (true_next_id, false_next_id) = if let Some(decision) = decision {
            if let Some(cond_info) = decision.conditions.iter().find(|c| c.id == *condition_id) {
                (cond_info.true_next, cond_info.false_next)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        mappings.push(Mapping {
            span: *span,
            kind: MappingKind::MCDCBranch {
                true_bcb,
                false_bcb,
                condition_id: *condition_id,
                true_next_id,
                false_next_id,
            },
        });
    }
}
