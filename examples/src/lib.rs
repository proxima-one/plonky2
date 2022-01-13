#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::hash::hash_types::{HashOut, HashOutTarget};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, Witness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
    use plonky2_field::field_types::Field;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// returns (x, y, circuit)
    /// not-too-simple test circuit representing the following:
    /// y = (x == a) ? f(x) : g(x)
    /// f(x) = x^2 + x + 1
    /// g(x) = 6x^2 + 2x + 3
    /// where a is a constant
    fn arithmetic_and_switch(a: u32) -> (Target, Target, CircuitData<F, C, D>) {
        // start with the standard cirucit config. It's probably way larger than necessary
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        builder.register_public_input(x);

        // f(x)
        let x_squared_plus_x = builder.arithmetic(1u32.into(), 1u32.into(), x, x, x);
        let f_x = builder.add_const(x_squared_plus_x, 1u32.into());

        // g(x)
        let six_x_squared_plus_two_x = builder.arithmetic(6u32.into(), 2u32.into(), x, x, x);
        let g_x = builder.add_const(six_x_squared_plus_two_x, 3u32.into());

        // x == a
        let _a = builder.constant(a.into());
        let x_minus_a = builder.sub(x, _a);
        // comparison works on lower-radix number systems. Gate degree for the splitter is the limb base,
        // so choose binary because it gives the smallest degree.
        // convert to binary by splitting x_minus_a into 64 base-2 limbs
        let x_minus_a_split = builder.split_le_base::<2>(x_minus_a, 64);
        let zero = builder.zero();
        let x_eq_a = builder.list_le(x_minus_a_split, vec![zero; 64], 1);

        // select f_x or g_x based on x_eq_a
        let y = builder.select(x_eq_a, f_x, g_x);
        builder.register_public_input(y);

        (x, y, builder.build::<C>())
    }

    #[test]
    #[ignore]
    fn test_arithmetic_and_switch() -> Result<()> {
        // build the circuit (see above)
        let (x, y, circuit) = arithmetic_and_switch(42);

        // set the public inputs via a PartialWitness
        // set x = 42. Then x == 0, so y should be f(x) = 1807
        let mut pw = PartialWitness::new();
        pw.set_target(x, 42u32.into());
        pw.set_target(y, 1807u32.into());

        // prove
        let proof = circuit.prove(pw)?;

        // verify
        circuit.verify(proof).expect("expected verifier to accept");

        // make another proof with different inputs.
        // this time, x = 420 => y should be g(x) = 1059243
        let mut pw = PartialWitness::new();
        pw.set_target(x, 420u32.into());
        pw.set_target(y, 1059243u32.into());

        let proof = circuit.prove(pw)?;
        circuit.verify(proof).expect("expected verifier to accept");

        Ok(())
    }

    #[test]
    #[ignore]
    #[should_panic]
    fn test_arithmetic_and_switch_invalid_proof() {
        let (x, y, circuit) = arithmetic_and_switch(6);

        // set x = 21. 21 != 6, so y should be g(x) = 2691, but set it to f(x) = 463 instead.
        let mut pw = PartialWitness::new();
        pw.set_target(x, 21u32.into());
        pw.set_target(y, 463u32.into());
        let _proof_should_panic = circuit.prove(pw);
    }

    /// example circuit that verifies a hash-chain containing N elements and N+1 hashes
    /// proof accepts if the hash chain verifies.
    /// retruns vec of wires for targets, wires for hashes, and the circuit.
    fn hash_chain(n: usize) -> (Vec<Target>, Vec<HashOutTarget>, CircuitData<F, C, D>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // create elem circuit input targets
        let xs = builder.add_virtual_targets(n);

        // create hash circuit input targets
        // a HashOutTarget is an array of 4 regular targets.
        let hashes = builder.add_virtual_hashes(n + 1);

        for i in 0..n {
            // unpack current hash circuit input into field elems, append elem, hash
            let mut prev_hash_as_targets = hashes[i].elements.to_vec();
            prev_hash_as_targets.push(xs[i]);
            let hash_out = builder.hash_n_to_hash::<PoseidonHash>(prev_hash_as_targets, true);

            // connect hash_out to next hash circuit input to enforce equality
            for j in 0..4 {
                builder.connect(hash_out.elements[j], hashes[i + 1].elements[j]);
            }
        }

        (xs, hashes, builder.build::<C>())
    }

    #[test]
    #[ignore]
    fn test_hash_chain() -> Result<()> {
        let (xs, hashes, circuit) = hash_chain(64);

        // generate random xs
        let mut rng = SmallRng::seed_from_u64(42);
        let x_values: Vec<F> = (0..64).map(|_| F::rand_from_rng(&mut rng)).collect();

        // compute hash chain
        let mut hash_values: Vec<HashOut<F>> = Vec::new();
        let first_hash = PoseidonHash::hash(vec![42u32.into()], true);
        hash_values.push(first_hash);

        for &x in x_values.iter() {
            let mut prev_hash_as_targets = hash_values.last().unwrap().elements.to_vec();
            prev_hash_as_targets.push(x);
            hash_values.push(PoseidonHash::hash(prev_hash_as_targets, true));
        }

        assert_eq!(hash_values.len(), 65);

        // load up partial witness
        let mut pw = PartialWitness::new();

        for i in 0..64 {
            pw.set_target(xs[i], x_values[i]);
            pw.set_hash_target(hashes[i], hash_values[i]);
        }
        pw.set_hash_target(hashes[64], hash_values[64]);

        let proof = circuit.prove(pw)?;
        circuit.verify(proof).expect("expected verifier to accept");

        Ok(())
    }
}
