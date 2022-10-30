use plonky2::field::{
	types::{Field, PrimeField64}
};
use tiny_keccak::{Hasher, Keccak};
use plonky2::hash::hash_types::RichField;
use crate::starky2lib::{
	rlp::generation::{RlpItem, RlpStarkGenerator, compute_str_prefix},
	stack::generation::StackOp
};
use plonky2_util::log2_ceil;
use rlp::encode;

pub enum TrieTemplate {
	NotLeaf {
		kind: NotLeafKind,
		plen: usize,
		path: [u8; 6],
		val_idx: Option<usize>,
		num_children: usize,
		children: [Option<Box<TrieTemplate>>; 16]
	},
	Leaf {
		plen: usize,
		path: [u8; 6],
		val_idx: usize
	}
}

pub enum NotLeafKind {
	Branch,
	Extension,
	CompressedLeaf,
}

impl Default for TrieTemplate {
	fn default() -> Self {
		TrieTemplate::NotLeaf {
			kind: NotLeafKind::Branch,
			plen: 0,
			path: [0; 6],
			val_idx: None,
			num_children: 0,
			children: [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None]
		}
	}
}

pub fn hash_rlpd_node(node: RlpItem) -> [u8; 32] {
	let encoded = encode(&node);
	let mut hasher = Keccak::v256();
	let mut hash = [0u8; 32];
	hasher.update(&encoded);
	hasher.finalize(&mut hash);
	hash
}

impl TrieTemplate {
	pub fn to_rlp_items(&self, leaves: &[Vec<u8>]) -> ([u8; 32], Vec<RlpItem>) {
		let mut res = Vec::new();			
		let root = self.to_rlp_items_inner(&mut res, leaves);
		(root, res)
	}

	fn to_rlp_items_inner(&self, items: &mut Vec<RlpItem>, leaves: &[Vec<u8>]) -> [u8; 32] {
		match self {
			TrieTemplate::NotLeaf { kind: NotLeafKind::Branch, children, val_idx, .. } => {
				let strs = children.iter().map(|child| match child {
					Some(child) => {
						let child_hash = child.to_rlp_items_inner(items, leaves);
						RlpItem::Str(child_hash.to_vec())
					},
					None => RlpItem::Str(vec![])
				}).collect();
				let item = RlpItem::list_from_vec(strs);
				items.push(item.clone());
				hash_rlpd_node(item)
			},
			TrieTemplate::NotLeaf { kind: NotLeafKind::Extension, children, plen, path, .. }  => {
				let encoded_path = path_to_prefixed_bytes(&path[..*plen], false);
				let i = children.iter().enumerate().find_map(|(i, c)| c.as_ref().map(|_| i)).unwrap();
				let child_hash = children[i].as_ref().unwrap().to_rlp_items_inner(items, leaves);
				let item = RlpItem::list_from_vec(vec![
					RlpItem::Str(encoded_path),
					RlpItem::Str(child_hash.to_vec())
				]);
				items.push(item.clone());
				hash_rlpd_node(item)
			}
			TrieTemplate::NotLeaf { kind: NotLeafKind::CompressedLeaf, val_idx, plen, path, .. } => {
				let encoded_path = path_to_prefixed_bytes(&path[..*plen], true);
				let value = leaves[val_idx.unwrap()].clone();
				let item = RlpItem::list_from_vec(vec![
					RlpItem::Str(encoded_path),
					RlpItem::Str(value)
				]);
				items.push(item.clone());
				hash_rlpd_node(item)
			}
			TrieTemplate::Leaf { plen, val_idx, path } => {
				let encoded_path = path_to_prefixed_bytes(&path[..*plen], true);
				let value = leaves[*val_idx].clone();
				let item = RlpItem::list_from_vec(vec![
					RlpItem::Str(encoded_path),
					RlpItem::Str(value)
				]);
				items.push(item.clone());
				hash_rlpd_node(item)
			}
		}
	}

	pub fn from_leaves(leaves: &[Vec<u8>]) -> Self {
		let mut res = Self::default();

		// build template
		for i in 0..leaves.len() {
			let path = path_from_idx(i);
			res.insert(&path, i);
		}

		res
	}

	// traverse through the template, and compress paths that can be compressed
	pub fn compress(&mut self) {
        match self {
			// if it's a leaf, then we've gotten to the bottom
			TrieTemplate::Leaf { .. } => {},
			// if it'sa NotLeaf, then check its number of children
			// if it has only one child, and it doesn't have a value, it can be coempressed
			TrieTemplate::NotLeaf { children, num_children, kind, plen, path, val_idx } => {
				if *num_children == 1 && val_idx.is_none() {
					let i = children.iter().enumerate().find_map(|(i, c)| c.as_ref().map(|_| i)).unwrap();
					let child = children[i].take().unwrap();
					let mut _path = vec![i as u8];
					let replacement = child.compress_inner(&mut _path);
					*plen = _path.len();
					path[..*plen].copy_from_slice(&_path);

					match replacement {
						TrieTemplate::Leaf { val_idx: child_val, .. } => {
							*kind = NotLeafKind::CompressedLeaf;
							*num_children = 0;
							*children = Default::default();
							*val_idx = Some(child_val);
						},
						TrieTemplate::NotLeaf { .. } => {
							*kind = NotLeafKind::Extension;
						}
					}
				} else {
					for child in children.iter_mut().filter_map(|c| c.as_mut()) {
						child.compress();
					}
				}
			}
		}			
	}

	fn compress_inner(mut self, path: &mut Vec<u8>) -> Self {
		match self {
			TrieTemplate::Leaf { .. } => self,
			TrieTemplate::NotLeaf { ref mut children, num_children, .. } => {
				if num_children == 1 {
					let i = children.iter().enumerate().find_map(|(i, c)| c.as_ref().map(|_| i)).unwrap();
					let child = children[i].take().unwrap();
					path.push(i as u8);
					child.compress_inner(path)
				} else {
					self
				}
			}
		}
	}

	fn insert(&mut self, path: &[u8], val_idx: usize) {
		match self {
			TrieTemplate::Leaf { .. } => unreachable!(),
			TrieTemplate::NotLeaf { val_idx: _val_idx, num_children, children, .. } => {
				assert_is_nibble(path[0]);
				let idx = path[0] as usize;
				match children[idx].as_mut() {
					Some(child) => {
						child.insert(&path[1..], val_idx);
					},
					None => {
						if path.len() == 1 {
							let child = TrieTemplate::Leaf {
								plen: 0,
								path: [0; 6],
								val_idx
							};
							children[idx] = Some(Box::new(child));
							*num_children += 1;
						} else {
							let mut child = TrieTemplate::default();
							child.insert(&path[1..], val_idx);
							children[idx] = Some(Box::new(child));
							*num_children += 1;
						}
					}
				}
			}
		}
	}
}

fn assert_is_nibble(val: u8) {
	assert!(val < 16);
}

pub fn path_to_prefixed_bytes(path: &[u8], is_leaf: bool) -> Vec<u8> {
	let mut nibbles = match (path.len() % 2, is_leaf) {
		(0, false) => vec![0x0, 0x0],
		(1, false) => vec![0x1],
		(0, true) => vec![0x2, 0x0],
		(1, true) => vec![0x3],
		_ => unreachable!()
	};
	nibbles.extend(path);
	assert!(nibbles.len() % 2 == 0);

	let mut res = Vec::new();
	for &[hi, lo] in nibbles.array_chunks() {
		res.push(hi << 4 | lo);
	}
	res
}

pub fn path_from_idx(i: usize) -> Vec<u8> {
	let i_bytes_len = if i == 1 { 1 } else { (log2_ceil(i) + 7) / 8 };
	let i_bytes = &i.to_be_bytes()[8 - i_bytes_len..];
	let first_val = i_bytes[0];
	let mut prefix = compute_str_prefix(i_bytes_len, first_val);

	prefix.extend(i_bytes);
	bytes_to_nibbles(&prefix)
}

pub fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
	let mut res = Vec::with_capacity(bytes.len() * 2);

	for byte in bytes {
		res.push(byte >> 4);
		res.push(byte & 0xf);
	}

	res
}