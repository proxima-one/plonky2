## Starky2

This is WIP prototype fork of `starky` but with a generic cross-table-lookup interface which can be used to share STARKs as if they were standalone modules. This document describes the current state of the project.

Currently, since the cross-table lookups are not yet implemented recursively (i.e. no `eval_cross_table_lookups_circuit`), this fork of starky doesn't support recursion yet.

### How to use `starky`

The general process of implementing a STARK proof with starky is:
1. define trace layout
2. implement trace generator
3. write constraints

At a high level, `starky2` has a "prove" function that takes a column-major 2-D array of field elements we call the "trace" (each column is interpreted as a polynomial). It has no built in way to generate it, nor any mechanisms to help you generate it. That prove function also takes as input a struct that implements the `Stark` trait, which details the expected size of the trace, the number of public inputs, and the contraints applied to every window of two adjacent rows.


#### Defining Trace Layout

`starky`'s interface for trace genreation is quite barebones - a row of the trace is simply an array of field elements. `starky` doesn't force you into any particular approach, but to stay sane we give names to the columns, either using constants (e.g. as done in [`starky2lib/sha256_compression/layout.rs`](./src/starky2lib/sha2_compression/layout.rs)) or using an unchecked transmute to a `repr(C)` struct as done in most of the other STARKs in `starky2lib` (e.g. [`starky2lib/ro_memory/layout.rs`](./src/starky2lib/ro_memory/layout.rs)). In both cases, we're just giving names to the indices of a trace row with a fixed number of columns.

> The `repr(C)` transmute trick used in most of the STARKs in `starky2lib` is completely safe bceause everey field of the `repr(C)` struct is either of type `T`, or an array of `T`s, which all have the same memory alignment. It's still quite hacky, but we use it here because it makes it much easier to change the layout and leads to clearner contraint code than using constants.


#### Implement Trace Generator

How you want to write this will vary greatly depending on what you're trying to implement. Usually it makes sense to write some kind of a "builder-like" struct with methods that allow you to "load up" operations. For a clean example of this, see [`xor`](./src/starky2lib/xor/generation.rs). For a more sophistocated example of this approach, see [`ecgfp5_vartime`](./src/starky2lib/ecgfp5_vartime/generation.rs). Other times, you're doing something much more complex and need to read long, structured inputs via a memory - in this case it often makes sense to write an easy way to "genreate" the memory (which will depend on the application) and a state machine that will generate the whole trace at once. For an example of this, see [`rlp`](./src/starky2lib/rlp/generation.rs).


Regardless of the method, you'll want to get the trace as a 2-D array of field elements in row-major order. To transpose it, call `util::trace_rows_to_poly_values` - this also wraps every column in a `PolynomialValues<F>`, giving `Vec<PolynomialValues<F>>`, which is the type that the "prove" funcitons accept.

#### Writing Constraints

Once you have your trace generator and layout, define an empty struct and implement the [`Stark` trait](./src/stark.rs) on it. Let's take a look at the head of the definition:
```rust
/// Represents a STARK system.
pub trait Stark<F: RichField + Extendable<D>, const D: usize>: Sync {
    /// The total number of columns in the trace.
    const COLUMNS: usize;
    /// The number of public inputs.
    const PUBLIC_INPUTS: usize;
	
	// ...
}
```

`COLUMNS` should be set to match the number of columns in your layout. `PUBLIC_INPUTS` is the number of public inputs (in field elements) your STARK expects. When you write your constraints, they too will be passed in simply as an array, so if you have a lot of them, give them names to stay sane. You write your constraints by implementing the `eval_packed_generic`:

```rust
    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;
```

The function signature is a bit of a beast, but it's not that bad - it only looks scary because `starky` uses a lot of const generics. `vars` is a struct containing three slices of `P`s, which are internally arrays of `FE`s, which are (elements of the degree-`D2` extension field of `F`). In practice you just treat it as if it was a field element - you can add, subtract, multiply, etc as if it was a cell in one row the trace you wrote the layout / generator for.

The first two slices are `local_values` and `next_values`, which abstractly represent the "current row" and the "next row" of the trace. The third slice, `public_inputs`, contains the public inputs. If you're using the "transmute" trick for your layout, you can "borrow" the slices as the `repr(C)` struct so you can access elements of the row as if they were named struct fields.

`yield_constr` is how you write your constraints. To write a constraint, you call one of the following methods on it:
* `yield_constr.constraint(expr)`: applies a constraint that is valid IFF `expr` is zero for every window of two adjacent rows, plus wraparound from the last to first row.
* `yield_constr.constraint_transition(expr)`: applies a constraint that is valid IFF `expr` for every window of two adjacent rows, excluding wrapround from the last to first row.
* `yield_constr.constraint_first_row(expr)`: same as the above, but only applies to the window containing the first and second rows.
* `yield_constr.constraint_last_row(expr)`: same as the above, but only applies to the window containing the second-to-last and last rows.

For each, `expr` is an expression containing only values from `local_values`, `next_values`, or `public_inputs`. 

> Under the hood, the `PackedField` elements in `local_values` and `next_values` are used by the prover to evaluate constraints over multiple rows of the trace the same time. When you write your constraints, they're applied exactly the same as if it wasn't evaluating a batch of rows at once, so you can treat it as if you were only writing a constraint from one row to the next.

For full examples of this, check out `mod.rs` in any of the starks in `starky2lib`.

To be able to verify the STARK proof in a `plonky2` SNARK, one must also implement the `eval_ext_circuit` method, which is similar but you must use a `plonky2` `CircuitBuilder` to generate circuitry for your constraint expression. However, for now this is moot since this isn't implemented for the cross-table lookups, and, due to the manner in which `starky` was originally written, wrapping the STARK proof in a `plonky2` proof is broken regardless of the cross-table lookups.

##### A Note on Constraint Degree

One of the arguments to the `prove` method (which we'll discuss in a moment) is a `StarkConfig`, which contains an important parameter `rate_bits`, which sets FRI's codeword rate. The maximum degree constraint supported is defined as `2^rate_bits + 1`. A smaller rate means a faster prover at the cost of a larger proof, and vice-verse with a larger rate.

Usually, we want to turn `rate_bits` all the way down to `1` because it leads to the fastest prover and we don't care about proof size because plonky2 recursion is really fast. While this means we're limited to degree-3 constraints, which sometimes requires us to use more columns, increasing `rate_bits` by 1 more than doubles the proof generation time. And for the vast majority of uses cases being able to use degree-5 constraints doesn't allow you to remove half of the columns, so its rarely worth it to bump up `rate_bits` in `starky`.

### Cross-Table Lookups and `AllStark`

The idea behind a cross-table lookup is that we have two (or more) STARKs, and we wish to perform a lookup argument (similar to plookup) where the looking column(s) and looked column(s) are in the tables *different* STARKs. This can be utilized to allow one STARK to "look up" the output of a complicated operation from another STARK specialized for that task. A variant of these are used by more or less every zkEVM built on STARKs.
> For example, a STARK that builds a merkle tree might "look up" the hashes from a specialized STARK that implements sha256

The idea behind how this codebase is structured is the following: as long as the "shape" of the lookup arguments are the same for two STARKs, they may be swapped out for different semantics, performance, etc.
> Continuing the previous example, since both `sha256` and `keccak` both return 32-byte digests, one can swap out sha256 for keccak256.

There are two reasons this is beneficial:
1. modularity
2. performance

Using this trick often leads to more performance because, roughly speaking, prover cost scales with the total area of all STARKs to be proven. That means if, say, if you're building a zkEVM that has to handle all kinds of complicated opcodes like hash functions, bigint arithmetic, etc, and you're putting it all into a single STARK, every step of execution will require circuitry for *all* opcodes, not just the one being executed at that moment. In other words, a STARK that only did, say, Keccak256 would require fewer columns than a STARK that had to select circuitry from one of 256 opcodes. By splitting it up, we can only pay for what we actually use.

Of course, cross-table lookups do come with overhead in addition to the overhead of having to prove multiple STARKs, not just one. So for small things it might not be worth it, but for the most part the things we want to build are non-trivial, so it's often quite worth it to delegate functionality that naturally fits into a narrow, long trace (e.g. memory) to a separate stark from "dependent" functionality that more naturally fits into a shorter, wider trace (e.g. hash functions). The modularity also makes actually writing stuff more manageable.

#### Terminology

Before moving onwards, we introduce some terminology for working with CTLs:
1. *table*: a STARK trace - in particular, the trace of a single component STARK vs the entire STARK.
2. *looked* and *looking*: in a lookup argument, we say a table is "looking" if the lookup argument is using a set of columns in that table as the "thing being looked up", and the corresponding "looked" table is the table the lookup argument is checking against.
3. *channels*: Sometimes several STARKs may utilize CTLs to delegate the same functionality to one STARK. An example of this is a memory, where two STARKs may check the contents of different subsets of the same memory. To keep them separate, we introduce the concept of a "channel", where the looked table can allocate a "channel" for each looking STARK. In practice, this is done with binary filters.

### Using Cross-Table Lookups via AllStark

Suppose we already had a stark implemented, including a layout, trace generator, and implementation of `Stark`. To use CTLs to generate a set of related proofs (which we call an `AllStarkProof`), one must implemeunt two traits:
1. `CtlStark`
2. `AllStark`

#### Implementing `CtlStark`

```rust
/// This trait is implemented by multi-trace STARKs that use cross-table lookups
/// This trait is used to configure which columns are to look up which other columns.
pub trait CtlStark<F: Field> {
    /// Data needed to generate all of the traces
    type GenData;

    /// returns the number of tables in this multi-trace STARK
    fn num_tables(&self) -> usize;

    /// returns a `CtlDescriptor`, which contains pairs `CtlColumn`s that represent each CTL to perform.
    /// IMPORTANT: This method establishes the ordering for extracing challenge points, so the ordering of the instances returned must be deterministic.
    /// see `CtlDescriptor` for more information
    fn get_ctl_descriptor(&self) -> CtlDescriptor;

    /// generate all of the traces
    /// returns (public_inputses, traces_poly_valueses)
    fn generate(
        &self,
        gen_data: Self::GenData,
    ) -> Result<(Vec<Vec<F>>, Vec<Vec<PolynomialValues<F>>>)>;
}
```

Lets go through each item:
1. `GenData`:  a type containing whatever data the `generate` method would need to generate all of the constituent STARK's traces via their trace generators.
2. `num_tables()` a method that returns the number of individual STARKs we'd like to tie together with cross-table lookups
3. `get_ctl_descriptor()`: a method that returns a struct whose contents declare which columns of which STARK are to "look up" which columns from which other STARK. More on this below.
4. `generate()`: a method that takes `GenData` and returns a tuple with two elements. The LHS is a vector of the public inputs for each STARK, where the `i`th public inputs are the public inputs for STARK `i`. the RHS is a vector of STARK traces, where the `i`th trace is for the STARK `i`. it's up to the you to ensure traces and public inputs are in the correct order.

the meat of this is `get_ctl_descriptor()`. Let's take a look at `CtlDescriptor`:
```rust
pub struct TableID(pub usize);

/// represets a set of cross-table lookups to be performed between an arbitrary number of starks on arbitrary sets of colums
#[derive(Debug, Clone)]
pub struct CtlDescriptor {
    /// instances of CTLs, where a colset in one table "looks up" a column in another table
    /// represented as pairs of columns where the LHS is a set of columns in some table "looking" up the RHS, another set of columns in some table
    pub instances: Vec<(CtlColSet, CtlColSet)>,
    /// the number of tables involved
    pub num_tables: usize,
}

/// Describes a set of columns that is involved in a cross-table lookup
/// These columns are "linked" together via a linear-combination. This
/// means the lookup effectively amounts to looking up a "tuple"
/// of columns up to the *same* permutations. In other words,
/// if a set of colums (a, b, c) in trace 0 is "looking up"
/// a set of columns in (x, y, z) in trace 1, then the lookup will
/// enforce that, for every row i in trace 0, there exists a row j in trace 1
/// such that (a[i], b[i], c[i]) = (x[j], y[j], z[j]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CtlColSet {
    /// table ID for the table that this column set belongs to
    pub(crate) tid: TableID,
    /// set of column indices for this side of the CTL
    pub(crate) colset: Vec<usize>,
    /// column index for the corresponding filter, if any
    pub(crate) filter_col: Option<usize>,
}
```

A `CtlDescriptor` contains a `Vec` of pairs `CtlColSet`s, whose `colset` field is an ordered list of columns from a particular STARK's table. The left hand `CtlColSet` of the pair is the "looking" colset, and the right hand `CtlColSet` of the pair is the "looked" colset. If `filter_col` is given, then a particular row is "ignored" by the lookup IFF the value in that column is 0 (i.e. it's "included" IFF it's 1). The lookup argument will then enforce that, for every row in the looking STARK's trace where the filter is set (of every row if no filter is given), the values of the columns in the looking `colset` are identical (according to order in which the cols are given) to the values of the columns in the looked `colset` at *some* row in the looked STARK's trace where the looked stark's filter is set (or any row of the lookked STARK's trace if no filter is set).

Therefore, writing `get_ctl_descriptor()`, more or less means collecting the lookup instances you wish to apply as pairs of `CtlColSet`s. In practice, we write helpers in our STARK's layouts for this. For instance, a memory access from the `rw_memory` requires four arguments: a flag indicating whether or not the access is a write, an address, a value, and a logical timestamp. 

A good way to do this is to implement helpers in each STARK's lookup that returns `CtlColSets` for each of the lookups it expects to make. The most clean / clear example of this can be found in [`starky2lib/xor/layout.rs`](./src/starky2lib/xor/layout.rs).

#### Implementing AllStark

This is a bit of a hack because `starky` is written entriely with static dispatch and for this prototype we didn't want to re-write a lot of starky. With dynamic dispatch, this trait can probably be implemented once for every implementor of `CtlStark`. That said, while it's a fair bit of boilerplate, it's very formulaic code to write that a proc macro could write.

```rust
/// This trait is implemented by multi-trace STARKs that use cross-table lookups
pub trait AllStark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>:
    CtlStark<F>
{
    // a type containing all of the `Stark` implementors for this multi-table STARK.
    type Starks;

    /// return instances of all of the `Stark` implementors
    fn get_starks(&self, config: &StarkConfig) -> Self::Starks;

    fn prove(
        &self,
        starks: &Self::Starks,
        config: &StarkConfig,
        trace_poly_valueses: &[Vec<PolynomialValues<F>>],
        public_inputses: &[Vec<F>],
        timing: &mut TimingTree,
    ) -> Result<AllProof<F, C, D>>;
    fn verify(
        &self,
        starks: &Self::Starks,
        config: &StarkConfig,
        proof: &AllProof<F, C, D>,
    ) -> Result<()>;
}

/// an aggregate multi-table STARK proof.
pub struct AllProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub proofs: Vec<StarkProofWithPublicInputs<F, C, D>>,
}
```

Again, the implementation of this should be fairly bording and formulaic. We show how to implement each. The simplest full example can be found in [`examples/depth_5_merkle_stark_sha2`](./examples/depth_5_merkle_stark_sha2.rs), and snippets given here are taken from there:

##### `Starks`

This should be just a tuple type where the `i`th type is the STARK whose corresponding trace is returned at index `i` from `CtlStark::generate()`. For example, for the merkle STARK, it contains the `Tree5Stark` from `depth_5_merkle_tree` and the `Sha2CompressionStark` from `sha2_compression`:

```rust
    type Starks = (Tree5Stark<F, D>, Sha2CompressionStark<F, D>);
```

##### `get_starks()`

This should be a thing that instantiates each `Stark` implementor and returns them as a `Starks`. For instance, for the merkle stark:

```rust
    fn get_starks(&self, _config: &StarkConfig) -> Self::Starks {
        let tree_stark = Tree5Stark::<F, D>::new();
        let sha2_stark = Sha2CompressionStark::<F, D>::new();
        (tree_stark, sha2_stark)
    }
```

##### `prove()`

There are four steps steps to `prove()`. First, compute the trace commitments for all of the STARKs and initialize the challenger by calling `start_all_proof`. Again, for the merkle stark, it looks like this:
```rust
    fn prove(
        &self,
        starks: &Self::Starks,
        config: &starky2::config::StarkConfig,
        trace_poly_valueses: &[Vec<PolynomialValues<F>>],
        public_inputses: &[Vec<F>],
        timing: &mut plonky2::util::timing::TimingTree,
    ) -> Result<AllProof<F, C, D>> {
        let (trace_commitments, mut challenger) =
            start_all_proof::<F, C, D>(config, trace_poly_valueses, timing)?;

        // ...
    }
```

under the hood, `start_all_proof` will have the challenger observe all of the trace commitments before returning, so the challenger is now ready to be used for anything that requires the trace commitment to have already been observed or "included in the transcript".

Second, we get the `CtlDescriptor` and compute the CTL polynomials (`CtlData`) from it by calling `get_ctl_data`. This will look something like this:
```rust
    let ctl_descriptor = self.get_ctl_descriptor();
    let ctl_data = get_ctl_data::<F, C, D>(
        config,
        trace_poly_valueses,
        &ctl_descriptor,
        &mut challenger,
    );
```

Third, for each STARK, we generate a proof using `prove_single_table`, which looks something like this:
```rust
// get the stark from the tuple
let stark = &starks.0;
// get that STARK's public inputs
let pis = public_inputses[0].clone().try_into()?;
// generate the proof
let proof = prove_single_table(
    stark,
    config,
    &trace_poly_valueses[0],
    &trace_commitments[0],
    Some(&ctl_data.by_table[0]),
    pis,
    &mut challenger,
    timing,
)?;
```

Fourth, put all of the proofs into a `Vec` and return an instance of `AllProof`. This amounts to fair bit of boilerplate, but it's pretty straightforward to write - mostly copy and paste. In principle this can be automated by a proc macro but for now this is what has to be done.

##### `verify()`

implementing `verify()` is similar to implementing `prove()`. First, we intitialize the challenger by calling `start_all_proof_challenger`, which looks something like this:
```rust
    fn verify(
        &self,
        starks: &Self::Starks,
        config: &StarkConfig,
        all_proof: &AllProof<F, C, D>,
    ) -> anyhow::Result<()> {
        let mut challenger = start_all_proof_challenger::<F, C, _, D>(
            all_proof.proofs.iter().map(|proof| &proof.proof.trace_cap),
        );

        // ...
    }
```

Under the hood, `start_all_proof_challenger` will observe the trace commitments contained in each of the proofs, so the challenger is now ready to be used for anything that requires the trace commitment to have already been observed or "included in the transcript", and, if the prover was honest, should have the same state the prover's challenger had after calling `start_all_proof`.

Second, we get the `CtlDescriptor`, challenges and evaluations by calling `get_ctl_descriptor()`, `get_ctl_challenges_by_table()`, and `CtlCheckVars::from_proofs`, which looks something like this:
```rust
    let num_challenges = config.num_challenges;

    let ctl_descriptor = self.get_ctl_descriptor();
    let (linear_comb_challenges, ctl_challenges) = get_ctl_challenges_by_table::<F, C, D>(
        &mut challenger,
        &ctl_descriptor,
        num_challenges,
    );

    let ctl_vars = CtlCheckVars::from_proofs(
        &all_proof.proofs,
        &ctl_descriptor,
        &linear_comb_challenges,
        &ctl_challenges,
    );
```

Third, we verify each of the STARK proofs:
```rust
    let stark = &starks.0;
    let proof = &all_proof.proofs[0];
    verify_stark_proof_with_ctl(stark, proof, &ctl_vars[0], &mut challenger, config)?;
```

Finally, we verify the cross-table lookup arguments:
```rust
verify_cross_table_lookups(
    all_proof.proofs.iter().map(|p| &p.proof),
    &ctl_descriptor,
    num_challenges,
)?;
```

For full examples see the [`examples`](./examples/) and/or the tests for each of the STARKs in [`starky2lib`](./src/starky2lib/).
