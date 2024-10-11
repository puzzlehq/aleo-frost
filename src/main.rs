use std::collections::HashMap;

use snarkvm_console_account::{private_key::*, compute_key::*, signature::*, Address, FromStr, ToFields, Zero};
use snarkvm_console_network::{Network, TestnetV0};
use snarkvm_console_program::Value;
use snarkvm_console_types::Scalar;
use snarkvm_console_types_scalar::TestRng;

use crate::{keys::trusted_keygen, preprocess::preprocess, frost::PartialThresholdSignature, utils::{calculate_binding_value, calculate_group_commitment}};

mod keys;
mod preprocess;
mod utils;
mod frost;

fn main() {
    let rng = &mut TestRng::default();
    let private_key = PrivateKey::<TestnetV0>::new(rng).unwrap();
    let compute_key = ComputeKey::<TestnetV0>::try_from(private_key).unwrap();
    let address = Address::<TestnetV0>::try_from(compute_key).unwrap();

    // message to verify
    let message = Value::<TestnetV0>::from_str("{ recipient: aleo1hy0uyudcr24q8nmxr8nlk82penl8jtqyfyuyz6mr5udlt0g3vyfqt9l7ew, amount: 10u128 }").unwrap().to_fields().unwrap();
    println!("message: {:?}", message);

    // vanilla sign & verify:

    let signature = private_key.sign(&message, rng).unwrap();
    let verified = signature.verify(&address, &message);
    assert!(verified);
    println!("signature verified with multisig private key (vanilla)");

    // FROST sign & verify:

    // construct FROST multisig shares from the private key
    let (shares, public_keys) = trusted_keygen(3, 2, &private_key.sk_sig(), rng);
    println!("key shares: {:?}", shares);
    println!("public keys: {:?}", public_keys);

    // Confirming that we can reconstruct the sk_sig from the new shares
    // let reconstructed_secret = reconstruct_secret(&shares).unwrap();
    // println!("Reconstructed secret is {:?}", reconstructed_secret);
    // println!("Does this match sk_sig? {:?}", reconstructed_secret.0 == private_key.sk_sig());

    // FROST round 1: Choosing 2 signers and computing preprocess round to generate signing nonces and singing commitments for signers 1 and 2
    println!("------- Round 1: Preprocessing  -------");
    let (signing_nonces_1, signing_commitments_1) = preprocess(1, 1, rng);
    let (signing_nonces_2, signing_commitments_2) = preprocess(1, 2, rng);
    println!("computed signing nonces and commitments");

    // Computing B from the two signing commitments
    let signing_commitments_b = vec![signing_commitments_1[0], signing_commitments_2[0]];

    // Constructing Partial signatures for the two signers
    println!("------- RoundD 2: Partial Signing & Aggregation  -------");
    println!("computing partial signaturess for signers 1 & 2 for 2/3 threshold...");
    let signer_share_1 = shares.iter().find(|share| share.participant_index == 1).unwrap();
    let partial_sig_1 = PartialThresholdSignature::new_partial_sig(
      &signer_share_1,
      &signing_nonces_1[0],
      signing_commitments_b.clone(),
      message.clone(),
      compute_key.pr_sig()
    ).unwrap();
    println!("partial signature 1: {:?}", partial_sig_1);
    let signer_share_2 = shares.iter().find(|share| share.participant_index == 2).unwrap();
    let partial_sig_2 = PartialThresholdSignature::new_partial_sig(
      &signer_share_2,
      &signing_nonces_2[0],
      signing_commitments_b.clone(),
      message.clone(),
      compute_key.pr_sig()
    ).unwrap();
    println!("partial signature 2: {:?}", partial_sig_2);

    // note: this is the point where threshold is reached

    // Construct the Partial Signatures Vec for the two signers
    let partial_signatures = vec![partial_sig_1, partial_sig_2];

    // Construct the aggregated response, threshold challenge and the complete signature
    let mut binding_values: HashMap<u64, Scalar<TestnetV0>> = HashMap::with_capacity(signing_commitments_b.len());
    for commitment in &signing_commitments_b {
      let rho_i = calculate_binding_value(commitment.participant_index, &signing_commitments_b, &message);
      binding_values.insert(commitment.participant_index, rho_i);
    }
    println!("binding values rho_i: {:?}", binding_values);

    // Calculate the group commitment -- ie g_r
    let group_commitment = calculate_group_commitment(&signing_commitments_b, &binding_values);
    println!("group commitment for multisig: {:?}", group_commitment);

    // Generate the challenge
    // Constructing the preimage for the challenge hash for the signature as (g_r, pk_sig, pr_sig, address, message).
    // note: reason for splicing into signature logic here is for group_commitment
    println!("constructing the hash preimage for the multisig challenge...");
    let mut multisig_preimage = Vec::with_capacity(4 + message.len());
    multisig_preimage.extend([
      group_commitment,
      compute_key.pk_sig(),
      compute_key.pr_sig(),
      *address
    ].map(|point|point.to_x_coordinate()));
    multisig_preimage.extend(&message);
    println!("hash preimage for multisig challenge: {:?}", multisig_preimage);

    // Compute the multisig challenge that verifier will receive
    println!("constructing the multisig challenge...");
    let multisig_challenge = Network::hash_to_scalar_psd8(&multisig_preimage).unwrap();
    println!("multisig challenge: {:?}", multisig_challenge);

    // Compute the response from the partial signature shares
    println!("constructing the multisig response...");
    let mut multisig_response = Scalar::<TestnetV0>::zero();
    for partial_signature in &partial_signatures {
        multisig_response = multisig_response + partial_signature.partial_signature;
    }
    println!("multisig response: {:?}", multisig_response);

    // create Signature from multisig_challenge, multisig_response, and compute_key
    println!("constructing multisig and verifying...");
    let multisig_signature = Signature::<TestnetV0>::from((multisig_challenge, multisig_response, compute_key));
    match multisig_signature.verify(&address, &message) {
      true => println!("verified 🟢"),
      false => println!("verified 🔴")
    };
}
