use std::collections::HashMap;

use crate::{keys::*, preprocess::*, utils::*};

use snarkvm_console_network::{Network, TestnetV0};
use snarkvm_console_types::{Group, Scalar};
use snarkvm_console_types_scalar::{anyhow, Field};
use snarkvm_console_account::{compute_key::*, Address};

use rand::Error;

/// A partial signature made by each participant of the t-out-of-n secret
/// sharing scheme where t is the threshold required to reconstruct
/// a secret from a total of n shares
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct PartialThresholdSignature {
    // The index of the participant
    pub participant_index: u64,
    // The participant's signature over the message
    pub partial_signature: Scalar<TestnetV0>,
}

/// Generate a new partial threshold signature for a participant.
///
/// `participant_signing_share` - Keys required for the participant to craft a signature.
/// `signing_nonce` - (private) The signing nonce the participant has kept secret.
/// `signing_commitments` - (public) Each participant's public signing commitment.
/// `message` - (public) The message to be signed.
///
/// z_i = d_i + (e_i * rho_i) + lambda_i * s_i * c
/// s_i = secret key
/// (d_i, e_i) = signing nonces
/// (G^d_i, G^e_i) = (D_i, E_i) = signing commitments
/// rho_i = binding value = H_1(i, message, signer's signing commitment)
/// lambda_i = Lagrange coefficient
/// c = challenge = H_2(group commitment, group public key, message)
impl PartialThresholdSignature {
    pub fn new_partial_sig(
        participant_signing_share: &SignerShare,
        signing_nonce: &SigningNonce,
        signing_commitments: Vec<SigningCommitment>,
        message: Vec<Field<TestnetV0>>,
        pr_sig: Group<TestnetV0>,
    ) -> Result<Self, Error> {
        // Calculating rho_i in order to calculate R
        let mut binding_values: HashMap<u64, Scalar<TestnetV0>> = HashMap::with_capacity(signing_commitments.len());
        for commitment in &signing_commitments {
            let rho_i = calculate_binding_value(commitment.participant_index, &signing_commitments, &message);
            binding_values.insert(commitment.participant_index, rho_i);
        }

        let signer_binding_value = binding_values
            .get(&participant_signing_share.participant_index)
            .ok_or_else(|| anyhow!("Missing binding value")).unwrap();

        // Calculate the group commitment R as Product of (Di*Ei^rho_i)*...(Dn*En^rho_n)
        let group_commitment = calculate_group_commitment(&signing_commitments, &binding_values);

        // Generate the challenge for the signature
        let address = Address::<TestnetV0>::try_from(ComputeKey::<TestnetV0>::try_from((participant_signing_share.group_public_key.0, pr_sig)).unwrap()).unwrap();
        
        let mut preimage = Vec::with_capacity(4 + message.len());
        preimage.extend([group_commitment, participant_signing_share.group_public_key.0, pr_sig, *address].map(|point| point.to_x_coordinate()));
        preimage.extend(message);

        let challenge = Network::hash_to_scalar_psd8(&preimage).unwrap();

        // Calculate the Lagrange coefficient
        let participant_indexes: Vec<u64> = signing_commitments.iter().map(|commitment| commitment.participant_index).collect();
        let lambda_i = calculate_lagrange_coefficients(participant_signing_share.participant_index, &participant_indexes).unwrap();

        // Calculating the response for the signature
        // z_i = d_i + (e_i * rho_i) - lambda_i * s_i * c
        let partial_signature = signing_nonce.hiding
            + (signing_nonce.binding * signer_binding_value)
            - (lambda_i * participant_signing_share.secret_key.0 * challenge);
        
        Ok(Self { participant_index: participant_signing_share.participant_index, partial_signature: partial_signature })
    }
}