## Starky2

This is WIP fork of `starky` but with a generic cross-table-lookup interface which can be used to share STARKs as if they were standalone modules.

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
	
	...

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

#### Using Cross-Table Lookups on existing STARK implementations

TODO:
* AllStark
* CtlDescriptor
* ColSets
* Column Helpers
* 
