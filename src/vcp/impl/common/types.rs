// ------------------------------------------------------------------------------
use crate::vcp::types::Warning;
// ------------------------------------------------------------------------------

/// Not used in API, to avoid complications with autogenerating the OpenAPI
/// from parametric types in API.  This is provided only as a convenience for
/// underlying library implementers.
pub struct WarningsAndResult<A> {
    pub warnings : Vec<Warning>,
    pub result   : A
}
