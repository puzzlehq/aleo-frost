use core::num;

use rand::Error;
use snarkvm_console_network::{Network, Testnet3};
use snarkvm_console_types::{Group, Scalar, U8, U64};
use snarkvm_console_types_scalar::{Uniform, FromField, ToField, One, Zero, Inverse};

// Calculate the Lagrange coefficient for a given participant index.
pub fn calculate_lagrange_coefficients(
    participant_index: u64,
    all_participant_indices: &[u64],
) -> Result<Scalar<Testnet3>, Error> {
    let mut numerator = Scalar::<Testnet3>::one();
    let mut denominator = Scalar::<Testnet3>::one();

    let participant_index_scalar = Scalar::<Testnet3>::from_field(&U64::new(participant_index).to_field().unwrap()).unwrap();

    for index in all_participant_indices {
        // Skip the index if it is the same as the participant index.
        if index == &participant_index {
            continue;
        }

        let scalar = Scalar::<Testnet3>::from_field(&U64::new(*index).to_field().unwrap()).unwrap();

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