use std::collections::HashMap;

use crate::{keys::*, preprocess::*, utils::*};

use snarkvm_console_network::{Network, Testnet3};
use snarkvm_console_types::{Group, Scalar, U8, U64};
use snarkvm_console_types_scalar::{Uniform, FromField, ToField, Zero, anyhow, Field, Itertools};
use snarkvm_console_account::{private_key::*, compute_key::*, view_key::*, signature::*, Address};

use rand::{Rng, Error};

/// A partial signature made by each participant of the t-out-of-n secret
/// sharing scheme where t is the threshold required to reconstruct
/// a secret from a total of n shares
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct PartialThresholdSignature {
    // The index of the participant
    pub participant_index: u64,
    // The participant's signature over the message
    pub partial_signature: Scalar<Testnet3>,
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
        message: Vec<Field<Testnet3>>,
        pr_sig: Group<Testnet3>,
    ) -> Result<Self, Error> {
        // Calculating rho_i in order to calculate R
        let mut binding_values: HashMap<u64, Scalar<Testnet3>> = HashMap::with_capacity(signing_commitments.len());
        for commitment in &signing_commitments {
            let rho_i = calculate_binding_value(commitment.participant_index, &signing_commitments, &message);
            binding_values.insert(commitment.participant_index, rho_i);
        }

        let signer_binding_value = binding_values
            .get(&participant_signing_share.participant_index)
            .ok_or_else(|| anyhow!("Missing binding value")).unwrap(); 

        // Calculate the group commitment R as Product of (Di*Ei^rho_i)*...(Dn*En^rho_n)
        println!("---------INSIDE FROST: committing nonce to use with signature---------"); 
        let group_commitment = calculate_group_commitment(&signing_commitments, &binding_values);
        println!("INSIDE FROST: g_r for multisig is {:?}", group_commitment);

        // Generate the challenge for the signature
        println!("---------INSIDE FROST: generating address for constructing the hash preimage for the signature's challenge---------");
        let address = Address::<Testnet3>::try_from(ComputeKey::<Testnet3>::try_from((participant_signing_share.group_public_key.0, pr_sig)).unwrap()).unwrap();
        println!("INSIDE FROST: address from compute key is {:?}", address);

        println!("---------INSIDE FROST: constructing the hash preimage for the signature's challenge---------");
        
        let mut preimage = Vec::with_capacity(4 + message.len());
        preimage.extend([group_commitment, participant_signing_share.group_public_key.0, pr_sig, *address].map(|point| point.to_x_coordinate()));
        preimage.extend(message);
        println!("INSIDE FROST: Hash preimage for signature challenge is {:?}", preimage);

        println!("---------INSIDE FROST: constructing the signature's challenge---------");
        let challenge = Network::hash_to_scalar_psd8(&preimage).unwrap();
        println!("INSIDE FROST: The challenge is {:?}", challenge);

        // Calculate the Lagrange coefficient
        println!("---------INSIDE FROST: constructing the lambda coefficient for the signature's response ---------");
        let participant_indexes: Vec<u64> = signing_commitments.iter().map(|commitment| commitment.participant_index).collect();
        println!("INSIDE FROST: Participant indexes is {:?}", participant_indexes);
        let lambda_i = calculate_lagrange_coefficients(participant_signing_share.participant_index, &participant_indexes).unwrap();
        println!("INSIDE FROST: Lambda is {:?}", lambda_i);

        // Calculating the response for the signature
        // z_i = d_i + (e_i * rho_i) - lambda_i * s_i * c
        let partial_signature = signing_nonce.hiding
            + (signing_nonce.binding * signer_binding_value)
            - (lambda_i * participant_signing_share.secret_key.0 * challenge);
        
        Ok(Self { participant_index: participant_signing_share.participant_index, partial_signature: partial_signature })
    }
}