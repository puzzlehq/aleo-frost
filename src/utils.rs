use std::collections::HashMap;

use rand::Error;
use snarkvm_console_network::{Network, TestnetV0};
use snarkvm_console_types::{Group, Scalar, U64};
use snarkvm_console_types_scalar::{FromField, ToField, One, Zero, Inverse, Field, anyhow};

use crate::preprocess::SigningCommitment;

// Calculate the Lagrange coefficient for a given participant index.
pub fn calculate_lagrange_coefficients(
    participant_index: u64,
    all_participant_indices: &[u64],
) -> Result<Scalar<TestnetV0>, Error> {
    let mut numerator = Scalar::<TestnetV0>::one();
    let mut denominator = Scalar::<TestnetV0>::one();

    let participant_index_scalar = Scalar::<TestnetV0>::from_field(&U64::new(participant_index).to_field().unwrap()).unwrap();

    for index in all_participant_indices {
        // Skip the index if it is the same as the participant index.
        if index == &participant_index {
            continue;
        }

        let scalar = Scalar::<TestnetV0>::from_field(&U64::new(*index).to_field().unwrap()).unwrap();

        numerator = numerator * scalar;
        denominator = denominator * (scalar - participant_index_scalar);
    }
    
    // skipping below checks on duplicate index or failed to invert denomitor
    // if denominator == G::ScalarField::zero() {
    //     return Err(anyhow!("There was a duplicate index"));
    // }

    // let inverted_denominator = match denominator.inverse() {
    //     Some(res) => res,
    //     None => return Err(anyhow!("Failed to invert denominator")),
    // };
    
    let inverted_denominator = denominator.inverse().unwrap();

    Ok(numerator * inverted_denominator)

}

/// Generating the binding value -- rho_i -- that ensures signature is unique for a particular 
/// signing set, set of commitments, and message
/// rho_i = H1(index, H(m), B)
/// 
/// Implemented their way by hashing message
pub fn calculate_binding_value(
    participant_index: u64,
    signing_commitments: &[SigningCommitment],
    message: &Vec<Field<TestnetV0>>,
) -> Scalar<TestnetV0> {
    // changed from the OG to input a Vec<Field> and to just use preset hash_to_scalar_psd4
    let message_hash = Network::hash_to_scalar_psd4(&message).unwrap().to_field().unwrap();

    let mut preimage = Vec::new();
    // Skipping adding string of FROST_SHA256 as field to preimage
    // added new line for participant_index_field to explicitly set network to TestnetV0
    let participant_index_field: Field<TestnetV0> = U64::new(participant_index).to_field().unwrap();
    preimage.push(participant_index_field);
    preimage.push(message_hash);

    for commitment in signing_commitments {
        let commitment_participant_index: Field<TestnetV0> = U64::new(commitment.participant_index).to_field().unwrap();
        preimage.push(commitment_participant_index);
        // the below two had to_x_coordinate and I'm unsure why....
        preimage.push(commitment.hiding.to_x_coordinate());
        preimage.push(commitment.binding.to_x_coordinate());
    }

    let result = Network::hash_to_scalar_psd4(&preimage).unwrap();

    result

}

/// Calculate the group commitment which is published as part of the joint Schnorr Signature
///
/// Note this is R as Product of (Di*Ei^rho_i)*...(Dn*En^rho_n)
/// 
/// Also note that this is not published as part of Schnorr Signature in Aleo's Randomizable Schnorr Signature Scheme
/// The only items published are challenge, response, and compute key
pub fn calculate_group_commitment(
    signing_commitments: &[SigningCommitment],
    binding_values: &HashMap<u64, Scalar<TestnetV0>>,
) -> Group<TestnetV0> {
    // Need to figure out if no to_projective issue -- see OG code commented out below
    // let mut accumulator = G::zero().to_projective();
    let mut accumulator = Group::<TestnetV0>::zero();

    for commitment in signing_commitments.iter() {
        // commenting out check on commitment equaling identity -- see OG code commented out below
        // if G::zero() == commitment.binding || G::zero() == commitment.hiding {
        //     return Err(anyhow!("Commitment equals the identity."));
        // }

        let rho_i = binding_values
            .get(&commitment.participant_index)
            .ok_or_else(|| anyhow!("No matching commitment index")).unwrap();
        // Need to see if to_projective is an issue -- see OG code commented out below
        // accumulator += commitment.hiding.to_projective() + (commitment.binding.mul(*rho_i))
        accumulator = accumulator + commitment.hiding + commitment.binding * rho_i;

    }

    // need to figure out if to_affine is an issue -- see OG code commented out below
    // Ok(accumulator.to_affine())
    accumulator
    
}

