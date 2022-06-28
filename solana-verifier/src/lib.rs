use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use plonky2::plonk::{
    proof::ProofWithPublicInputs,
    config::PoseidonGoldilocksConfig,
};
use plonky2_field::goldilocks_field::GoldilocksField;

type GoldilocksProofWithPis = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

// Declare and export the program's entrypoint
entrypoint!(process_instruction);

// Program entrypoint's implementation
pub fn process_instruction(
    program_id: &Pubkey, // Public key of the account the hello world program was loaded into
    accounts: &[AccountInfo], // The account to say hello to
    _instruction_data: &[u8], // Ignored, all helloworld instructions are hellos
) -> ProgramResult {
    msg!("solana verifier program entrypoint");

    // Iterating accounts is safer then indexing
    let accounts_iter = &mut accounts.iter();

    // get circuit data account
    let circuit_data_account = next_account_info(accounts_iter)?;
    // Get proof account
    let proof_account = next_account_info(accounts_iter)?;

    // The account must be owned by the program in order to modify its data
    if proof_account.owner != program_id {
        msg!("proof account is not owned by the program!");
        return Err(ProgramError::IncorrectProgramId);
    }

    // Increment and store the number of times the account has been greeted
    let proof = GoldilocksProofWithPis::from_bytes_slice(&proof_account.data.borrow())?;

    Ok(())
}

// Sanity tests
#[cfg(test)]
mod test {
    use super::*;
    use solana_program::clock::Epoch;
    use std::mem;

    #[test]
    fn test_sanity() {
        let program_id = Pubkey::default();
        let key = Pubkey::default();
        let mut lamports = 0;
        let mut data = vec![0; mem::size_of::<u32>()];
        let owner = Pubkey::default();
        let account = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data,
            &owner,
            false,
            Epoch::default(),
        );
        let instruction_data: Vec<u8> = Vec::new();

        let accounts = vec![account];

        // assert_eq!(
        //     GreetingAccount::try_from_slice(&accounts[0].data.borrow())
        //         .unwrap()
        //         .counter,
        //     0
        // );
        // process_instruction(&program_id, &accounts, &instruction_data).unwrap();
        // assert_eq!(
        //     GreetingAccount::try_from_slice(&accounts[0].data.borrow())
        //         .unwrap()
        //         .counter,
        //     1
        // );
        // process_instruction(&program_id, &accounts, &instruction_data).unwrap();
        // assert_eq!(
        //     GreetingAccount::try_from_slice(&accounts[0].data.borrow())
        //         .unwrap()
        //         .counter,
        //     2
        // );
    }
}