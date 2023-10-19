use std::collections::HashMap;

use snarkvm_console_account::{private_key::*, compute_key::*, view_key::*, signature::*, Address, Uniform, FromStr, ToFields, Zero};
use snarkvm_console_network::{Network, Testnet3};
use snarkvm_console_program::Value;
use snarkvm_console_types::{Field, Scalar, Group};
use snarkvm_console_types_scalar::TestRng;

use crate::{keys::{trusted_keygen, reconstruct_secret}, preprocess::{preprocess, SigningCommitment}, frost::PartialThresholdSignature, utils::{calculate_binding_value, calculate_group_commitment}};

mod keys;
mod preprocess;
mod utils;
mod frost;

fn main() {
    // Create account seed
    println!("---------starting rng---------");
    let rng = &mut TestRng::default();
    println!("---------rng is created---------");

    // Generate the private key for the multisig account
    println!("---------creating standard Aleo Randomized Schnorr Private Key---------");
    let private_key = PrivateKey::<Testnet3>::new(rng).unwrap();
    println!("private key seed is {:?}", private_key.seed());
    println!("private key sk_sig is {:?}", private_key.sk_sig());
    println!("private key r_sig is {:?}", private_key.r_sig());

    // Generate the compute key for the multisig account
    println!("---------creating standard Aleo Randomized Schnorr Compute Key---------");
    let compute_key = ComputeKey::<Testnet3>::try_from(private_key).unwrap();
    println!("compute key pk_sig is {:?}", compute_key.pk_sig());
    println!("compute key pr_sig is {:?}", compute_key.pr_sig());
    println!("compute key sk_prf is {:?}", compute_key.sk_prf());

    // Generate the view key for the multisig account
    println!("---------creating standard Aleo Randomized Schnorr View Key---------");
    let view_key = ViewKey::<Testnet3>::try_from(private_key).unwrap();
    println!("view key is {:?}", view_key);

    // Generate the address for the multisig account
    println!("---------creating standard Aleo Randomized Schnorr Address---------");
    let address = Address::<Testnet3>::try_from(compute_key).unwrap();
    println!("address from compute key is {:?}", address);

    // Producing a signature with this account before keyshares
    println!("---------creating standard Aleo Randomized Schnorr Signature---------");
    println!("------------------------------------------------------------------------");

    // Create a value to be signed.
    println!("---------creating a value to be signed---------");
    let value = Value::<Testnet3>::from_str("{ recipient: aleo1hy0uyudcr24q8nmxr8nlk82penl8jtqyfyuyz6mr5udlt0g3vyfqt9l7ew, amount: 10u128 }").unwrap();
    println!("Message value is {:?}", value);

    // Transform the message into a field
    println!("---------turning a message value into fields to be signed---------");
    let message = value.to_fields().unwrap();
    println!("Message as fields is {:?}", message);

    // Create a nonce to use with signature
    println!("---------creating a nonce to use with signature---------");
    let nonce = Scalar::<Testnet3>::rand(rng);
    println!("Nonce for signature is {:?}", nonce);

    // Committing to nonce
    println!("---------committing nonce to use with signature---------");
    let g_r = Network::g_scalar_multiply(&nonce);
    println!("G_r for signature is {:?}", g_r);

    // Constructing the preimage for the challenge hash for the signature as (g_r, pk_sig, pr_sig, address, message).
    println!("---------constructing the hash preimage for the signature's challenge---------");
    let mut preimage = Vec::with_capacity(4 + message.len());
    preimage.extend([g_r, compute_key.pk_sig(), compute_key.pr_sig(), *address].map(|point| point.to_x_coordinate()));
    preimage.extend(&message);
    println!("Hash preimage for signature challenge is {:?}", preimage);

    // Compute the challenge that verifier will receive
    println!("---------constructing the signature's challenge---------");
    let challenge = Network::hash_to_scalar_psd8(&preimage).unwrap();
    println!("The challenge is {:?}", challenge);

    // Compute the response that the verifier will receive
    println!("---------constructing the signature's response---------");
    let response = nonce - (challenge * private_key.sk_sig());
    println!("The response is {:?}", response);

    // Casting to signature type
    println!("---------constructing the signature's from response, challenge, and compute_key ---------");
    let signature = Signature::<Testnet3>::from((challenge, response, compute_key));
    println!("The signature is {:?}", signature);

    // Verifying a signature with this account before keyshares
    println!("---------Verifying a standard Aleo Randomized Schnorr Signature---------");
    println!("------------------------------------------------------------------------");

    // Constructing candidate g_r
    println!("---------costructing candidate nonce to use with candidate challenge from signature response, challenge, and compute key---------");
    let candidate_g_r = Network::g_scalar_multiply(&signature.response()) + (compute_key.pk_sig() * signature.challenge());
    println!("candidate g_r is {:?}", candidate_g_r);

    // Constructing the preimage for the candidate challenge hash for the signature as (candidate_g_r, pk_sig, pr_sig, address, message).
    println!("---------constructing the hash preimage for the candidate challenge to verify---------");
    let mut candidate_preimage = Vec::with_capacity(4 + &message.len());
    candidate_preimage.extend([candidate_g_r, signature.compute_key().pk_sig(), signature.compute_key().pr_sig(), *address].map(|point|point.to_x_coordinate()));
    candidate_preimage.extend(message);
    println!("candidate preimage is {:?}", candidate_preimage);

    // Construct the candidate challenge from the candidate preimage
    println!("---------constructing the candidate challenge from the candidate preimage to verify---------");
    let candidate_challenge = Network::hash_to_scalar_psd8(&candidate_preimage).unwrap();
    println!("candidate challenge is {:?}", candidate_challenge);

    // Derive an address from the compute key
    println!("---------constructing the candidate address from the signature compute key to verify---------");
    let candidate_address = Address::try_from(signature.compute_key()).unwrap();
    println!("candidate address is {:?}", candidate_address);

    // Check that candidate challenge == challenge and that candidate_address == address
    println!("------- checking candidate challenge == challenge && candidate_address == address");
    let verify = signature.challenge() == candidate_challenge && *address == *candidate_address;
    println!("is signature verified? {:?}", verify);

    // Constructing a FROST Aleo Multisig out of the private key
    println!("------- Constructing FROST Keyshares from sk_sig---------");
    let (shares, public_keys) = trusted_keygen(3, 2, &private_key.sk_sig(), rng);
    println!("Key shares are {:?}", shares);
    println!("public keys for key shares are {:?}", public_keys);

    // Confirming that we can reconstruct the sk_sig from the new shares
    println!("------- Reconstructing sk_sig from FROST Keyshares ---------");
    let reconstructed_secret = reconstruct_secret(&shares).unwrap();
    println!("Reconstructed secret is {:?}", reconstructed_secret);
    println!("Does this match sk_sig? {:?}", reconstructed_secret.0 == private_key.sk_sig());

    // FROST round 1: Choosing 2 signers and computing preprocess round to generate signing nonces and singing commitments for signers 1 and 2
    println!("------- RD 1: Preprocessing  ---------");
    println!("------- Computing nonces for 2 out of 3 signing  ---------");
    let (signing_nonces_1, signing_commitments_1) = preprocess(1, 1, rng);
    let (signing_nonces_2, signing_commitments_2) = preprocess(1, 2, rng);
    println!("Signing nonces for signer 1 is {:?}", signing_nonces_1);
    println!("Signing commitments for signer 1 is {:?}", signing_commitments_1);
    println!("Signing nonces for signer 2 is {:?}", signing_nonces_2);
    println!("Signing commitments for signer 2 is {:?}", signing_commitments_2);

    // Computing B from the two signing commitments
    println!("------- Computing B from the 2 nonce commitments  ---------");
    let mut signing_commitments_b = Vec::with_capacity(2);
    signing_commitments_b.push(signing_commitments_1[0]);
    signing_commitments_b.push(signing_commitments_2[0]);
    println!("Signing commitments B for the two signer session is {:?}", signing_commitments_b);

    // Constructing Partial signatures for the two signers
    println!("------- RD 2: Partial Signing & Aggregation  ---------");
    println!("------- Computing partial sigs for signers 1 & 2 for 2 out of 3 signing  ---------");
    let cloned_value = Value::<Testnet3>::from_str("{ recipient: aleo1hy0uyudcr24q8nmxr8nlk82penl8jtqyfyuyz6mr5udlt0g3vyfqt9l7ew, amount: 10u128 }").unwrap();
    println!("Cloned Message value is {:?}", cloned_value);
    let cloned_message = cloned_value.to_fields().unwrap();
    println!("Cloned Message as fields is {:?}", cloned_message);

    let signer_share_1 = shares.iter().find(|share| share.participant_index == 1).unwrap();
    let partial_sig_1 = PartialThresholdSignature::new_partial_sig(&signer_share_1, &signing_nonces_1[0], signing_commitments_b.clone(), cloned_message.clone(), compute_key.pr_sig()).unwrap();
    println!("Partial sig 1 is {:?}", partial_sig_1);
    let signer_share_2 = shares.iter().find(|share| share.participant_index == 2).unwrap();
    let partial_sig_2 = PartialThresholdSignature::new_partial_sig(&signer_share_2, &signing_nonces_2[0], signing_commitments_b.clone(), cloned_message.clone(), compute_key.pr_sig()).unwrap();
    println!("Partial sig 2 is {:?}", partial_sig_2);

    // Construct the Partial Signatures Vec for the two signers
    println!("------- Computing partial sigs vec for signers 1 & 2 for 2 out of 3 signing  ---------");
    let mut partial_signatures = Vec::with_capacity(2);
    partial_signatures.push(partial_sig_1);
    partial_signatures.push(partial_sig_2);

    // Construct the aggregated response, threshold challenge and the complete signature
    let multisig_value = Value::<Testnet3>::from_str("{ recipient: aleo1hy0uyudcr24q8nmxr8nlk82penl8jtqyfyuyz6mr5udlt0g3vyfqt9l7ew, amount: 10u128 }").unwrap();
    println!("Multisig Message value is {:?}", multisig_value);
    let multisig_message = multisig_value.to_fields().unwrap();
    println!("Multisig Message as fields is {:?}", multisig_message);


    let mut binding_values: HashMap<u64, Scalar<Testnet3>> = HashMap::with_capacity(signing_commitments_b.len());
    for commitment in &signing_commitments_b {
        let rho_i = calculate_binding_value(commitment.participant_index, &signing_commitments_b, &multisig_message);
        binding_values.insert(commitment.participant_index, rho_i);
    }
    println!("binding values rho_i are {:?}", binding_values);

    // Calculate the group commitment -- ie g_r
    let group_commitment = calculate_group_commitment(&signing_commitments_b, &binding_values);
    println!("g_r for multisig is {:?}", group_commitment);


    // Generate the challenge
    // Constructing the preimage for the challenge hash for the signature as (g_r, pk_sig, pr_sig, address, message).
    println!("---------constructing the hash preimage for the signature's challenge---------");
    let mut multisig_preimage = Vec::with_capacity(4 + multisig_message.len());
    multisig_preimage.extend([group_commitment, compute_key.pk_sig(), compute_key.pr_sig(), *address ].map(|point|point.to_x_coordinate()));
    multisig_preimage.extend(multisig_message);
    println!("Multisig hash preimage for signature challenge is {:?}", multisig_preimage);

    // Compute the multisig challenge that verifier will receive
    println!("---------constructing the signature's challenge---------");
    let multisig_challenge = Network::hash_to_scalar_psd8(&multisig_preimage).unwrap();
    println!("The challenge is {:?}", multisig_challenge);

    // Compute the response from the partial signature shares
    println!("---------constructing the multisig's signature response---------");
    let mut multisig_response = Scalar::<Testnet3>::zero();
    for partial_signature in &partial_signatures {
        multisig_response = multisig_response + partial_signature.partial_signature;
    }
    println!("The multisig response is {:?}", multisig_response);


    // Casting to signature type
    println!("---------constructing the multisig signature from multisig_response, multisig_challenge, and compute_key ---------");
    let multisig_signature = Signature::<Testnet3>::from((multisig_challenge, multisig_response, compute_key));
    println!("The signature is {:?}", multisig_signature);

    // Verifying a multisig signature with this account
    println!("---------Verifying a FROST Aleo Randomized Schnorr Signature---------");
    println!("------------------------------------------------------------------------");
    let multisig_verify_value = Value::<Testnet3>::from_str("{ recipient: aleo1hy0uyudcr24q8nmxr8nlk82penl8jtqyfyuyz6mr5udlt0g3vyfqt9l7ew, amount: 10u128 }").unwrap();
    println!("Multisig Verify Message value is {:?}", multisig_verify_value);
    let multisig_verify_message: Vec<Field<Testnet3>> = multisig_verify_value.to_fields().unwrap();
    println!("Multisig Verify Message as fields is {:?}", multisig_verify_message);


    // Constructing candidate g_r
    println!("---------Multisig costructing candidate nonce to use with candidate challenge from signature response, challenge, and compute key---------");
    let multisig_candidate_g_r = Network::g_scalar_multiply(&multisig_signature.response()) + (compute_key.pk_sig() * multisig_signature.challenge());
    println!("candidate g_r is {:?}", multisig_candidate_g_r);

    // Constructing the preimage for the candidate challenge hash for the signature as (candidate_g_r, pk_sig, pr_sig, address, message).
    println!("---------Multisig constructing the hash preimage for the candidate challenge to verify---------");
    let mut multisig_candidate_preimage = Vec::with_capacity(4 + &multisig_verify_message.len());
    multisig_candidate_preimage.extend([multisig_candidate_g_r, multisig_signature.compute_key().pk_sig(), multisig_signature.compute_key().pr_sig(), *address].map(|point|point.to_x_coordinate()));
    multisig_candidate_preimage.extend(multisig_verify_message);
    println!("candidate preimage is {:?}", multisig_candidate_preimage);

    // Construct the candidate challenge from the candidate preimage
    println!("---------Multisig constructing the candidate challenge from the candidate preimage to verify---------");
    let multisig_candidate_challenge = Network::hash_to_scalar_psd8(&multisig_candidate_preimage).unwrap();
    println!("candidate challenge is {:?}", multisig_candidate_challenge);

    // Derive an address from the compute key
    println!("---------Multisig constructing the candidate address from the signature compute key to verify---------");
    let multisig_candidate_address = Address::try_from(multisig_signature.compute_key()).unwrap();
    println!("candidate address is {:?}", multisig_candidate_address);


    // Check that candidate challenge == challenge and that candidate_address == address
    println!("------- checking candidate challenge == challenge && candidate_address == address");
    let multisig_verify = multisig_signature.challenge() == multisig_candidate_challenge && *address == *multisig_candidate_address;
    println!("is FROST signature verified? {:?}", multisig_verify);


}
