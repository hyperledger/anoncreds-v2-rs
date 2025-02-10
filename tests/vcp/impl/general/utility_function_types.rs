// ---------------------------------------------------------------------------
use credx::vcp::{types::*, VCPResult};
// ---------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
// ---------------------------------------------------------------------------

pub type AccumsForSigner =
    HashMap<CredAttrIndex, (AccumulatorData,
                            // Original accumulator
                            Accumulator,
                            // For sequence number n, the update info to update a
                            // witness for nth accumulator to witness for (n+1)st
                            // accumulator, plus the (n+1)st accumulator itself
                            HashMap<AccumulatorBatchSeqNo, (AccumWitnessUpdateInfo, Accumulator)>)>;

pub type CreateAccumulators = Arc<
    dyn Fn(
        Natural, // RNG seed
        &[ClaimType],
    ) -> VCPResult<AccumsForSigner>
        + Send
        + Sync,
>;

pub type AccumulatorAddRemoveWithMap = Arc<
    dyn Fn(
            &AccumsForSigner,
            CredAttrIndex,
            &HashMap<HolderID, AccumulatorElement>,
            &[AccumulatorElement],
        ) -> VCPResult<AccumulatorAddRemoveWithMapResponse>
        + Send
        + Sync,
>;

pub type GetAccumulatorFromMap = Arc<
    dyn Fn(&AccumsForSigner, CredAttrIndex, AccumulatorBatchSeqNo) -> VCPResult<Accumulator>
        + Send
        + Sync,
>;

pub type GetAccumulatorPublicDataFromMap = Arc<
    dyn Fn(&AccumsForSigner, CredAttrIndex) -> VCPResult<AccumulatorPublicData>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccumulatorAddRemoveWithMapResponse {
    pub public_update_info: AccumWitnessUpdateInfo,
    pub wits_for_new: HashMap<HolderID, AccumulatorMembershipWitness>,
    pub updated_accum_map: AccumsForSigner,
    pub updated_accum_value: Accumulator,
}

// ---------------------------------------------------------------------------
