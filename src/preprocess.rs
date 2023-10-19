use snarkvm_console_network::{Network, Testnet3};
use snarkvm_console_types::{Group, Scalar, U8, U64};
use snarkvm_console_types_scalar::{Uniform, FromField, ToField, One, Zero, Inverse};

use rand::{Rng, Error};

// The hiding and binding nonces used (only once) for signing operation
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct SigningNonce {
    // d\_{ij}
    pub(crate) hiding: Scalar<Testnet3>,
    // e\_{ij}
    pub(crate) binding: Scalar<Testnet3>,
}

impl SigningNonce {
    pub fn new<R: Rng>(
        rng: &mut R
    ) -> Self {
        Self { hiding: (Scalar::<Testnet3>::rand(rng)), binding: (Scalar::<Testnet3>::rand(rng)) }
    }
}

// A precomputed commitment share
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct SigningCommitment {
    // The index of the participant.
    pub(crate) participant_index: u64,
    // The hiding commitment - D\_{ij}
    pub(crate) hiding: Group<Testnet3>,
    // The binding commitment - E\_{ij}
    pub(crate) binding: Group<Testnet3>,
}

impl SigningCommitment {
    // Generate the commitment share for a given participant index using a provided nonce
    pub fn from(
        participant_index: u64,
        nonce: &SigningNonce
    ) -> Self {
        Self {
            participant_index,
            hiding: Network::g_scalar_multiply(&nonce.hiding),
            binding: Network::g_scalar_multiply(&nonce.binding),
        }
    }
}

/// Performs the pre-computation of nonces and commitments used by each participant during signiing
/// 
/// Every participant must call this function to enable signing. In the case of a two-round Frost protocol,
/// then 'num_nonces' should be set to 1.
/// 
/// SigningNonce should be kept secret, while SigningCommitment should be distributed to other participants
pub fn preprocess<R: Rng> (
    num_nonces: usize,
    participant_index: u64,
    rng: &mut R,
) -> (Vec<SigningNonce>, Vec<SigningCommitment>) {
    let mut signing_nonces = Vec::with_capacity(num_nonces);
    let mut signing_commitments = Vec::with_capacity(num_nonces);

    for _ in 0..num_nonces {
        let nonce = SigningNonce::new(rng);
        let commitment = SigningCommitment::from(participant_index, &nonce);
        signing_nonces.push(nonce);
        signing_commitments.push(commitment);
    }

    (signing_nonces, signing_commitments)
}
