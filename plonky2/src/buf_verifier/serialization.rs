use std::marker::PhantomData;
use byteorder::{LittleEndian, ByteOrder};
use plonky2_field::types::{Field, PrimeField64};
use plonky2_field::extension::FieldExtension;
use crate::plonk::config::{GenericConfig, Hasher, GenericHashOut};
use crate::hash::merkle_tree::MerkleCap;

#[allow(type_alias_bounds)]
type HashForConfig<C: GenericConfig<D>, const D: usize> = <C::Hasher as Hasher<<C as GenericConfig<D>>::F>>::Hash;

pub struct ProofBuf<'a, C: GenericConfig<D>, const D: usize>{
	buf: &'a [u8],
	offsets: ProofBufOffsets,
	_phantom: PhantomData<C>,
}


pub struct ProofBufMut<'a, C: GenericConfig<D>, const D: usize> {
	buf: &'a mut [u8],
	offsets: ProofBufOffsets,
	_phantom: PhantomData<C>,
}

#[derive(Debug, Clone, Copy)]
struct ProofBufOffsets {
	len: usize,
	wires_cap_offset: usize,
	zs_pp_cap_offset: usize,
	quotient_polys_cap_offset: usize,
	constants_offset: usize,
	plonk_sigmas_offset: usize,
	wires_offset: usize,
	plonk_zs_offset: usize,
	pps_offset: usize,
	quotient_polys_offset: usize,
	plonk_zs_next_offset: usize,
	// The following offsets should all be initially set to `plonk_zs_next_offset`.
	// once the verifier computes the challenges, they should be updated accordingly
	challenge_betas_offset: usize,
	challenge_gammas_offset: usize,
	challenge_alphas_offset: usize,
	challenge_zeta_offset: usize,
	fri_alpha_offset: usize,
	fri_pow_response_offset: usize,
	fri_betas_offset: usize,
	fri_query_indices_offset: usize,
}

	// TODO: check to ensure offsets are valid and return a result
	fn get_offsets<'a>(buf: &'a [u8]) -> (ProofBufOffsets, usize) {
		let original_len = buf.len();

		let len = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let wires_cap_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let zs_pp_cap_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let quotient_polys_cap_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let constants_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let plonk_sigmas_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let wires_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let plonk_zs_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let pps_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let quotient_polys_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let plonk_zs_next_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let challenge_betas_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let challenge_gammas_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let challenge_alphas_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let challenge_zeta_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let fri_alpha_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let fri_pow_response_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let fri_betas_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];

		let fri_query_indices_offset = LittleEndian::read_u64(buf) as usize;
		let buf = &buf[std::mem::size_of::<u64>()..];
		

		(
			ProofBufOffsets {
				len,
				wires_cap_offset,
				zs_pp_cap_offset,
				quotient_polys_cap_offset,
				constants_offset,
				plonk_sigmas_offset,
				wires_offset,
				plonk_zs_offset,
				pps_offset,
				quotient_polys_offset,
				plonk_zs_next_offset,
				challenge_betas_offset,
				challenge_gammas_offset,
				challenge_alphas_offset,
				challenge_zeta_offset,
				fri_alpha_offset,
				fri_pow_response_offset,
				fri_betas_offset,
				fri_query_indices_offset,
			},
			buf.len() - original_len
		)
	}

impl<'a, C: GenericConfig<D>, const D: usize> ProofBuf<'a, C, D> {
	pub fn new(buf: &'a [u8]) -> Self {
		let (offsets, start_offset) = get_offsets(buf);
		ProofBuf { buf: &buf[start_offset..], offsets, _phantom: PhantomData }
	}

	pub fn read_pis_hash(&self) -> HashForConfig<C, D> {
		let hash_bytes = &self.buf[..<C as GenericConfig<D>>::Hasher::HASH_SIZE];
		HashForConfig::<C, D>::from_bytes(hash_bytes)
	}

	pub fn read_wires_cap(&self) -> MerkleCap<C::F, C::Hasher> {
		let width = (self.offsets.zs_pp_cap_offset - self.offsets.wires_cap_offset) / C::Hasher::HASH_SIZE;
		self.read_merkle_cap(self.offsets.wires_cap_offset, width)
	}

	pub fn read_zs_pp_cap(&self) -> MerkleCap<C::F, C::Hasher> {
		let width = (self.offsets.quotient_polys_cap_offset - self.offsets.zs_pp_cap_offset) / C::Hasher::HASH_SIZE;
		self.read_merkle_cap(self.offsets.zs_pp_cap_offset, width)
	}

	pub fn read_quotient_polys_cap(&self) -> MerkleCap<C::F, C::Hasher> {
		let width = (self.offsets.constants_offset - self.offsets.quotient_polys_cap_offset) / C::Hasher::HASH_SIZE;
		self.read_merkle_cap(self.offsets.quotient_polys_cap_offset, width)
	}

	pub fn read_constants_openings(&self) -> Vec<C::FE> {
		let len = (self.offsets.plonk_sigmas_offset - self.offsets.constants_offset) / (std::mem::size_of::<u64>() * D);
		self.read_field_ext_vec(self.offsets.constants_offset, len)
	}

	pub fn read_plonk_sigmas_openings(&self) -> Vec<C::FE> {
		let len = (self.offsets.wires_offset - self.offsets.plonk_sigmas_offset)/ (std::mem::size_of::<u64>() * D);
		self.read_field_ext_vec(self.offsets.plonk_sigmas_offset, len)
	}

	pub fn read_wires_openings(&self) -> Vec<C::FE> {
		let len = (self.offsets.plonk_zs_offset - self.offsets.wires_offset)/ (std::mem::size_of::<u64>() * D);
		self.read_field_ext_vec(self.offsets.wires_offset, len)
	}

	pub fn read_plonk_zs_openings(&self) -> Vec<C::FE> {
		let len = (self.offsets.pps_offset - self.offsets.plonk_zs_offset)/ (std::mem::size_of::<u64>() * D);
		self.read_field_ext_vec(self.offsets.plonk_zs_offset, len)
	}

	pub fn read_pps_openings(&self) -> Vec<C::FE> {
		let len = (self.offsets.quotient_polys_offset - self.offsets.pps_offset)/ (std::mem::size_of::<u64>() * D);
		self.read_field_ext_vec(self.offsets.pps_offset, len)
	}	

	pub fn read_quotient_polys_openings(&self) -> Vec<C::FE> {
		let len = (self.offsets.plonk_zs_next_offset - self.offsets.quotient_polys_offset)/ (std::mem::size_of::<u64>() * D);
		self.read_field_ext_vec(self.offsets.quotient_polys_offset, len)
	}

	pub fn read_plonk_zs_next_openings(&self) -> Vec<C::F> {
		let len = (self.offsets.challenge_betas_offset - self.offsets.plonk_zs_next_offset)/ (std::mem::size_of::<u64>() * D);
		self.read_field_vec(self.offsets.plonk_zs_next_offset, len)
	}

	pub fn read_challenge_betas(&self) -> Vec<C::F> {
		let len = (self.offsets.challenge_gammas_offset - self.offsets.challenge_betas_offset) / std::mem::size_of::<u64>();
		self.read_field_vec(self.offsets.challenge_betas_offset, len)
	}

	pub fn read_challenge_gammas(&self) -> Vec<C::F> {
		let len = (self.offsets.challenge_alphas_offset - self.offsets.challenge_gammas_offset) / std::mem::size_of::<u64>();
		self.read_field_vec(self.offsets.challenge_gammas_offset, len)
	}

	pub fn read_challenge_alphas(&self) -> Vec<C::F> {
		let len = (self.offsets.challenge_zeta_offset - self.offsets.challenge_alphas_offset) / std::mem::size_of::<u64>();
		self.read_field_vec(self.offsets.challenge_alphas_offset, len)
	}

	pub fn read_challenge_zeta(&self) -> C::FE {
		self.read_field_ext(self.offsets.challenge_zeta_offset)
	}

	pub fn read_fri_alpha(&self) -> C::FE {
		self.read_field_ext(self.offsets.fri_alpha_offset)		
	}

	pub fn read_fri_pow_response(&self) -> C::F {
		C::F::from_canonical_u64(LittleEndian::read_u64(&self.buf[self.offsets.fri_pow_response_offset..]))
	}

	pub fn read_fri_betas(&self) -> Vec<C::FE> {
		let len = (self.offsets.fri_query_indices_offset - self.offsets.fri_betas_offset) / (std::mem::size_of::<u64>() * D);
		self.read_field_ext_vec(self.offsets.fri_betas_offset, len)
	}

	pub fn read_fri_query_indices(&self) -> Vec<usize> {
		let len = (self.offsets.len - self.offsets.fri_query_indices_offset) / std::mem::size_of::<u64>();
		self.read_usize_vec(self.offsets.fri_query_indices_offset, len)
	}

	pub fn read_merkle_cap(&self, offset: usize, width: usize) -> MerkleCap<C::F, C::Hasher>
	{
		let cap_bytes = &self.buf[offset..];
		let mut hashes = Vec::new();
		for i in 0..width {
			let hash_bytes = &cap_bytes[i * <C::Hasher as Hasher<<C as GenericConfig<D>>::F>>::HASH_SIZE..];
			hashes.push(HashForConfig::<C, D>::from_bytes(hash_bytes));
		}

		MerkleCap(hashes)
	}

	pub fn read_field_ext(&self, offset: usize) -> C::FE {
		let bytes = &self.buf[offset..];
		let mut basefield_arr = [C::F::ZERO; D];
		for i in 0..D {
			basefield_arr[i] = C::F::from_canonical_u64(LittleEndian::read_u64(&bytes[i * std::mem::size_of::<u64>()..]));
		}

		C::FE::from_basefield_array(basefield_arr)
	}

	pub fn read_field_ext_vec(&self, mut offset: usize, len: usize) -> Vec<C::FE>
	{
		let mut res = Vec::with_capacity(len);
		for _ in 0..len {
			let field_ext = self.read_field_ext(offset);
			res.push(field_ext);
			offset += std::mem::size_of::<u64>() * D;
		}
		res
	}

	pub fn read_field_vec(&self, offset: usize, len: usize) -> Vec<C::F>
	{
		let mut res = Vec::with_capacity(len);
		let buf = &self.buf[offset..];
		for i in 0..len {
			res.push(C::F::from_canonical_u64(LittleEndian::read_u64(&buf[i * std::mem::size_of::<u64>()..])));
		}

		res
	}

	pub fn read_usize_vec(&self, offset: usize, len: usize) -> Vec<usize> {
		let mut res = Vec::with_capacity(len);
		let buf = &self.buf[offset..];
		for i in 0..len {
			res.push(LittleEndian::read_u64(&buf[i * std::mem::size_of::<u64>()..]) as usize);
		}

		res
	}
}

pub struct StreamingVerifierChallenges<C: GenericConfig<D>, const D: usize> {
	betas: Vec<C::F>,
	gammas: Vec<C::F>,
	alphas: Vec<C::F>,
	zeta: C::FE,
	fri_alpha: C::FE,
	fri_pow_response: C::F,
	fri_betas: Vec<C::FE>,
	fri_query_indices: Vec<usize>,
}

impl<'a, C: GenericConfig<D>, const D: usize> ProofBufMut<'a, C, D> {
	pub fn new(buf: &'a mut [u8]) -> Self {
		let (offsets, start_offset) = get_offsets(buf);
		ProofBufMut { buf: &mut buf[start_offset..], offsets, _phantom: PhantomData }
	}

	pub fn as_readonly<'b>(&'a self) -> ProofBuf<'b, C, D>
	where
		'a: 'b
	{
		ProofBuf { buf: self.buf, offsets: self.offsets, _phantom: PhantomData }
	}


	pub fn write_challenges(&mut self, challenges: StreamingVerifierChallenges<C, D>) {
		self.write_challenge_betas(&challenges.betas);
		self.write_challenge_gammas(&challenges.gammas);
		self.write_challenge_alphas(&challenges.alphas);
		self.write_challenge_zeta(challenges.zeta);
		self.write_fri_alpha(challenges.fri_alpha);
		self.write_fri_pow_response(challenges.fri_pow_response);
		self.write_fri_betas(&challenges.fri_betas);
		self.write_fri_query_indices(&challenges.fri_query_indices);
	}

	fn write_challenge_betas(&mut self, betas: &[C::F]) {
		self.write_field_vec(self.offsets.challenge_betas_offset, betas);
		self.offsets.challenge_gammas_offset = self.offsets.challenge_betas_offset + betas.len() * std::mem::size_of::<u64>();
	}

	fn write_challenge_gammas(&mut self, gammas: &[C::F]) {
		self.write_field_vec(self.offsets.challenge_gammas_offset, gammas);
		self.offsets.challenge_alphas_offset = self.offsets.challenge_gammas_offset + gammas.len() * std::mem::size_of::<u64>();
	}

	fn write_challenge_alphas(&mut self, alphas: &[C::F]) {
		self.write_field_vec(self.offsets.challenge_alphas_offset, alphas);
		self.offsets.challenge_zeta_offset = self.offsets.challenge_alphas_offset + alphas.len() * std::mem::size_of::<u64>();
	}

	fn write_challenge_zeta(&mut self, zeta: C::FE) {
		self.write_field_ext(self.offsets.challenge_zeta_offset, zeta);
		self.offsets.fri_alpha_offset = self.offsets.challenge_zeta_offset + std::mem::size_of::<u64>() * D;
	}

	fn write_fri_alpha(&mut self, alpha: C::FE) {
		self.write_field_ext(self.offsets.fri_alpha_offset, alpha);
		self.offsets.fri_pow_response_offset = self.offsets.fri_alpha_offset + std::mem::size_of::<u64>() * D;
	}

	fn write_fri_pow_response(&mut self, pow_response: C::F) {
		let buf = &mut self.buf[self.offsets.fri_pow_response_offset..];
		LittleEndian::write_u64(buf, pow_response.to_canonical_u64());
		self.offsets.fri_betas_offset = self.offsets.fri_pow_response_offset + std::mem::size_of::<u64>();
	}

	fn write_fri_betas(&mut self, fri_betas: &[C::FE]) {
		self.write_field_ext_vec(self.offsets.fri_betas_offset, fri_betas);
		self.offsets.fri_query_indices_offset = self.offsets.fri_betas_offset + std::mem::size_of::<u64>() * D * fri_betas.len();
	}

	fn write_fri_query_indices(&mut self, fri_query_indices: &[usize]) {
		self.write_usize_vec(self.offsets.fri_query_indices_offset, fri_query_indices);
		self.offsets.len = self.offsets.fri_query_indices_offset + std::mem::size_of::<u64>() * fri_query_indices.len();
	}

	fn write_field_ext_vec(&mut self, mut offset: usize, fri_betas: &[C::FE]) {
		for i in 0..fri_betas.len() {
			self.write_field_ext(offset, fri_betas[i]);
			offset += std::mem::size_of::<u64>() * D;
		}
	}

	fn write_field_vec(&mut self, offset: usize, elems: &[C::F]) {
		let mut buf = &mut self.buf[offset..];
		for elem in elems {
			LittleEndian::write_u64(&mut buf[0..std::mem::size_of::<u64>()], elem.to_canonical_u64());
			buf = &mut buf[std::mem::size_of::<u64>()..];
		}
	}

	fn write_usize_vec(&mut self, offset: usize, elems: &[usize]) {
		let mut buf = &mut self.buf[offset..];
		for elem in elems {
			LittleEndian::write_u64(&mut buf[0..std::mem::size_of::<u64>()], *elem as u64);
			buf = &mut buf[std::mem::size_of::<u64>()..];
		}
	}

	fn write_field_ext(&mut self, offset: usize, elem: C::FE) {
		let buf = &mut self.buf[offset..];
		let basefield_arr = elem.to_basefield_array();
		for i in 0..D {
			LittleEndian::write_u64(&mut buf[i * std::mem::size_of::<u64>()..], basefield_arr[i].to_canonical_u64());
		}
	}
}