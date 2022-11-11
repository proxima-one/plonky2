use plonky2_util::log2_ceil;
use rlp::encode;
use tiny_keccak::{Hasher, Keccak};

use crate::starky2lib::{
    rlp::generation::{compute_str_prefix, RlpItem},
};

pub enum TrieTemplate {
    NotLeaf {
        kind: NotLeafKind,
        plen: usize,
        path: [u8; 6],
        val_idx: Option<usize>,
        num_children: usize,
        children: [Option<Box<TrieTemplate>>; 16],
    },
    Leaf {
        plen: usize,
        path: [u8; 6],
        val_idx: usize,
    },
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
            children: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
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
            TrieTemplate::NotLeaf {
                kind: NotLeafKind::Branch,
                children,
                val_idx,
                ..
            } => {
                let mut strs: Vec<RlpItem> = children
                    .iter()
                    .map(|child| match child {
                        Some(child) => {
                            let child_hash = child.to_rlp_items_inner(items, leaves);
                            RlpItem::Str(child_hash.to_vec())
                        }
                        None => RlpItem::Str(vec![]),
                    })
                    .collect();
                let val = match val_idx {
                    Some(i) => leaves[*i].clone(),
                    None => vec![],
                };

                strs.push(RlpItem::Str(val));

                let item = RlpItem::list_from_vec(strs);
                items.push(item.clone());
                hash_rlpd_node(item)
            }
            TrieTemplate::NotLeaf {
                kind: NotLeafKind::Extension,
                children,
                plen,
                path,
                ..
            } => {
                let encoded_path = path_to_prefixed_bytes(&path[..*plen], false);
                let i = children
                    .iter()
                    .enumerate()
                    .find_map(|(i, c)| c.as_ref().map(|_| i))
                    .unwrap();
                let child_hash = children[i]
                    .as_ref()
                    .unwrap()
                    .to_rlp_items_inner(items, leaves);
                let item = RlpItem::list_from_vec(vec![
                    RlpItem::Str(encoded_path),
                    RlpItem::Str(child_hash.to_vec()),
                ]);
                items.push(item.clone());
                hash_rlpd_node(item)
            }
            TrieTemplate::NotLeaf {
                kind: NotLeafKind::CompressedLeaf,
                val_idx,
                plen,
                path,
                ..
            } => {
                let encoded_path = path_to_prefixed_bytes(&path[..*plen], true);
                let value = leaves[val_idx.unwrap()].clone();
                let item =
                    RlpItem::list_from_vec(vec![RlpItem::Str(encoded_path), RlpItem::Str(value)]);
                items.push(item.clone());
                hash_rlpd_node(item)
            }
            TrieTemplate::Leaf {
                plen,
                val_idx,
                path,
            } => {
                let encoded_path = path_to_prefixed_bytes(&path[..*plen], true);
                let value = leaves[*val_idx].clone();
                let item =
                    RlpItem::list_from_vec(vec![RlpItem::Str(encoded_path), RlpItem::Str(value)]);
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
            TrieTemplate::Leaf { .. } => {}
            // if it'sa NotLeaf, then check its number of children
            // if it has only one child, and it doesn't have a value, it can be coempressed
            TrieTemplate::NotLeaf {
                children,
                num_children,
                kind,
                plen,
                path,
                val_idx,
            } => {
                if *num_children == 1 && val_idx.is_none() {
                    let i = children
                        .iter()
                        .enumerate()
                        .find_map(|(i, c)| c.as_ref().map(|_| i))
                        .unwrap();
                    let child = children[i].take().unwrap();
                    let mut _path = vec![i as u8];
                    let replacement = child.compress_inner(&mut _path);
                    *plen = _path.len();
                    path[..*plen].copy_from_slice(&_path);

                    match replacement {
                        TrieTemplate::Leaf {
                            val_idx: child_val, ..
                        } => {
                            *kind = NotLeafKind::CompressedLeaf;
                            *num_children = 0;
                            *children = Default::default();
                            *val_idx = Some(child_val);
                        }
                        TrieTemplate::NotLeaf { .. } => {
                            *kind = NotLeafKind::Extension;
                            children[i] = Some(Box::new(replacement))
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
            TrieTemplate::NotLeaf {
                ref mut children,
                num_children,
                val_idx,
                ..
            } => {
                if num_children == 1 && val_idx.is_none() {
                    let i = children
                        .iter()
                        .enumerate()
                        .find_map(|(i, c)| c.as_ref().map(|_| i))
                        .unwrap();
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
            TrieTemplate::NotLeaf {
                val_idx: _val_idx,
                num_children,
                children,
                ..
            } => {
                assert_is_nibble(path[0]);
                let idx = path[0] as usize;
                match children[idx].as_mut() {
                    Some(child) => {
                        child.insert(&path[1..], val_idx);
                    }
                    None => {
                        if path.len() == 1 {
                            let child = TrieTemplate::Leaf {
                                plen: 0,
                                path: [0; 6],
                                val_idx,
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
        _ => unreachable!(),
    };
    nibbles.extend(path);
    assert!(nibbles.len() % 2 == 0);

    let mut res = Vec::new();
    for &[hi, lo] in nibbles.array_chunks() {
        res.push(hi << 4 | lo);
    }
    res
}

pub fn rlp_encode_idx(i: usize) -> Vec<u8> {
    let i_bytes_len = if i == 1 { 1 } else { (log2_ceil(i) + 7) / 8 };
    let i_bytes = &i.to_be_bytes()[8 - i_bytes_len..];

    let first_val = if i_bytes_len == 0 { 0 } else { i_bytes[0] };
    let mut prefix = compute_str_prefix(i_bytes_len, first_val);

    prefix.extend(i_bytes);
    prefix
}

pub fn path_from_idx(i: usize) -> Vec<u8> {
    let bytes = rlp_encode_idx(i);
    bytes_to_nibbles(&bytes)
}

pub fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut res = Vec::with_capacity(bytes.len() * 2);

    for byte in bytes {
        res.push(byte >> 4);
        res.push(byte & 0xf);
    }

    res
}

pub fn nibbles_to_bytes(nibbles: NibbleSlice) -> Vec<u8> {
    let mut res = Vec::with_capacity(nibbles.len() / 2);

    for &[hi, lo] in nibbles.array_chunks() {
        res.push(hi << 4 | lo);
    }

    res
}

pub fn compressed_path_prefix(path: NibbleSlice, is_leaf: bool) -> Vec<u8> {
    match (path.len() % 2, is_leaf) {
        (0, false) => vec![0x0, 0x0],
        (1, false) => vec![0x1],
        (0, true) => vec![0x2, 0x0],
        (1, true) => vec![0x3],
        _ => unreachable!(),
    }
}

pub fn encode_compressed_path_to_bytes(path: NibbleSlice, is_leaf: bool) -> Vec<u8> {
    let mut nibbles = compressed_path_prefix(path, is_leaf);
    nibbles.extend(path);
    nibbles_to_bytes(&nibbles)
}

type NibbleSlice<'a> = &'a [u8];

// if val < 32 bytes, pad it with zeroes up to 32 bytes.
// this needed because this trie impl only works with values >= 32 bytes
pub fn leaf_val(val: &[u8]) -> Vec<u8> {
    let mut val = val.to_vec();
    if val.len() < 32 {
        val.resize(32, 0);
    }
    val
}

// pub struct TrieBuilderSM<F: PrimeField64> {
//     rlp_mem: Vec<F>,
//     call_stack: Vec<F>,
//     call_stack_trace: Vec<StackOp<F>>,
//     // len, array of (addr, len) tuples, values
//     value_mem: Vec<F>,
//     // len, array of (addr, len) tuples, values
//     sorted_path_mem: Vec<F>,
//     /// array of 32-byte hashes of RLP'd nodes
//     hash_mem: Vec<F>,

//     values: Vec<Vec<u8>>,
//     sorted_paths: Vec<Nibbles>,

//     node_id: usize,

//     // pointer nto rlp mem
//     ap: usize,

//     // indexes of sorted paths.
//     // this is used to determine when we've reached a leaf and when we need to compress
//     lo: usize,
//     hi: usize,
//     depth: usize,

//     state: TrieBuilderState,
//     trace: Vec<IdxKeyedTrieRow<F>>
// }

// enum TrieBuilderState {
//     /// write the empty string into the rlp memory
//     Init,

//     /// special cases
//     EmptyTrie,
//     SingleValueTrie,

//     /// observe an entry in the rlp memory before we check its semantics
//     ObserveNode,

//     /// count how many nibbles a compressed path has
//     Compress,

//     /// check compressed path entry of a two-element list
//     CheckCompressedPath,

//     /// check leaf value
//     CheckLeafValue,

//     /// return to the parent node.
//     /// if we're at the root, halt
//     /// otherwise, if we've 
//     Return,

//     Halt
// }

// const MAX_DEPTH: usize = 6;

// impl<F: PrimeField64> TrieBuilderSM<F> {
//     pub fn new(rlp_mem: Vec<F>, values: Vec<Vec<u8>>, hash_mem: Vec<F>) -> Self {
//         let mut value_mem = vec![F::ZERO; values.len() * 2 + 1];
//         value_mem[0] = F::from_canonical_usize(values.len());
//         for (i, value) in values.iter().enumerate() {
//             value_mem[i * 2 + 1] = F::from_canonical_usize(value_mem.len());
//             value_mem[(i + 1) * 2] = F::from_canonical_usize(value.len());
//             value_mem.extend(value.iter().map(|b| F::from_canonical_u8(*b)));
//         }

//         let sorted_paths = (1..values.len()).map(|i| path_from_idx(i)).sorted().collect_vec();
//         let mut sorted_path_mem = vec![F::ZERO; sorted_paths.len() * 2 + 1];
//         sorted_path_mem[0] = F::from_canonical_usize(sorted_paths.len());
//         for (i, path) in sorted_paths.iter().enumerate() {
//             sorted_path_mem[i * 2 + 1] = F::from_canonical_usize(sorted_path_mem.len());
//             sorted_path_mem[(i + 1) * 2] = F::from_canonical_usize(path.len());
//             sorted_path_mem.extend(path.iter().map(|b| F::from_canonical_u8(*b)));
//         }

//         Self {
//             ap: 0,
//             lo: 0,
//             node_id: 1,
//             depth: 0,
//             hi: values.len(),
//             state: TrieBuilderState::Init,

//             trace: vec![],
//             rlp_mem,
//             hash_mem,
//             call_stack: vec![],
//             call_stack_trace: vec![],
//             value_mem,
//             sorted_path_mem,
//             values,
//             sorted_paths,
//         }
//     }

//     fn read_value_mem(&self, addr: usize, _row: &mut IdxKeyedTrieRow<F>) -> F {
//         self.value_mem[addr]
//     }

//     fn get_path_nibble(&self, idx: usize, depth: usize) -> F {
//         let addr = self.sorted_path_mem[idx * 2 + 1];

//         self.sorted_path_mem[addr.to_canonical_u64() as usize + depth]
//     }

//     fn get_path_len(&self, idx: usize) -> F {
//         self.sorted_path_mem[idx * 2 + 2]
//     }

//     fn write_rlp_mem(&self, addr: usize, value: F) {
//         let got = self.rlp_mem[addr];
//         assert_eq!(got, value);
//     }

//     fn push_rlp_mem(&mut self, value: F) {
//         self.write_rlp_mem(self.ap, value);
//         self.ap += 1;
//     }

//     fn push_read_rlp_mem(&mut self) -> F {
//         let value = self.rlp_mem[self.ap];
//         self.ap += 1;
//         value
//     }

//     fn push_call_stack(&mut self, val: F) {
//         self.call_stack.push(val);
//         self.call_stack_trace.push(StackOp::Push(val))
//     }

//     fn pop_call_stack(&mut self) -> F {
//         let val = self.call_stack.pop().unwrap();
//         self.call_stack_trace.push(StackOp::Pop(val));
//         val
//     }

//     fn next_range(&mut self, lo: usize) -> (usize, usize) {
//         let mut next_hi = lo;
//         while next_hi < self.hi && self.get_path_nibble(next_hi, self.depth + 1) == self.get_path_nibble(self.lo, self.depth + 1) {
//             next_hi += 1;
//         }

//         (lo, next_hi)
//     }

//     fn slice_check_rlp_against_val(&mut self, mut rlp_start: usize, mut val_start: usize, mut len: usize) -> bool {
//         while rlp_start < self.rlp_mem.len() && val_start < self.value_mem.len() && len > 0 {
//             let rlp_val = self.rlp_mem[rlp_start];
//             let val_val = self.value_mem[val_start];

//             if rlp_val != val_val {
//                 return false;
//             }

//             rlp_start += 1;
//             val_start += 1;
//             len -= 1;
//         }

//         if len == 0 {
//             true
//         } else {
//             false
//         }
//     }

//     fn slice_check_rlp_against_hash(&mut self, mut rlp_start: usize) -> bool {
//         let mut hash_ptr = 32 * self.node_id; 
//         for i in 0..32 {
//             let rlp_val = self.rlp_mem[rlp_start + i];
//             let hash_val = self.rlp_mem[hash_ptr + i];

//             if rlp_val != hash_val {
//                 return false;
//             }

//             rlp_start += 1;
//             hash_ptr += 1;
//         }

//         true
//     }

//     pub fn generate(&mut self) {
//         loop {
//             let mut row = IdxKeyedTrieRow::<F>::new();
//             match self.state {
//                 TrieBuilderState::Init => {
//                     // check initial state
//                     let num_kvs = self.read_value_mem(0, &mut row).to_canonical_u64() as usize;
//                     assert_eq!(self.hi, num_kvs);
//                     assert_eq!(self.lo, 0);
//                     assert_eq!(self.ap, 0);
//                     assert_eq!(self.node_id, 1);

//                     self.state = match num_kvs {
//                         // handle special cases
//                         0 => TrieBuilderState::EmptyTrie,
//                         1 => TrieBuilderState::SingleValueTrie,
//                         _ => {
//                             // write empty string entry into RLP memory

//                             // next_item is 5 since the empty string is 5 cells long
//                             self.push_rlp_mem(F::from_canonical_usize(5));
//                             // is_last_item = false
//                             self.push_rlp_mem(F::from_bool(false));
//                             // is_list = false
//                             self.push_rlp_mem(F::from_bool(false));
//                             // id = 0
//                             self.push_rlp_mem(F::ZERO);
//                             // len = 0
//                             self.push_rlp_mem(F::ZERO);

//                             self.ap = 5;

//                             // transition to ObserveNode
//                             TrieBuilderState::ObserveNode
//                         }
//                     }
//                 },
//                 TrieBuilderState::ObserveNode => {
//                     // read entry metadata 
//                     let next_item = self.push_read_rlp_mem().to_canonical_u64() as usize;
//                     let is_last_item = self.push_read_rlp_mem().to_canonical_u64() == 1;
//                     let is_list = self.push_read_rlp_mem().to_canonical_u64() == 1;
//                     let id = self.push_read_rlp_mem().to_canonical_u64() as usize;
//                     let len = self.push_read_rlp_mem().to_canonical_u64() as usize;

//                     // check what we can check now
//                     assert_eq!(self.node_id, id);
//                     assert_eq!(is_list, true);

//                     if self.lo == self.hi {
//                         // leaf
//                         assert_eq!(len, 2);

//                         // in the stark, we can get these from the "previous" row
//                         // here, we push thm
//                         let len = self.get_path_len(self.lo);
//                         self.push_call_stack(len - F::from_canonical_usize(self.depth));
//                         self.push_call_stack(F::from_bool(true));

//                         self.state = TrieBuilderState::CheckCompressedPath;
//                     } else {
//                         // calculate lo/hi one level deeper
//                         let (_, next_hi) = self.next_range(self.lo);
//                         // NOTE: we can set self.hi here, as in the stack we can just compare next and curr.
//                         // the tmp here is just to express that easier outside the the STARK
//                         if self.hi == next_hi {
//                             // extension or leaf node - need to compress
//                             assert_eq!(len, 2);

//                             // in the stark, we can get these from the "previous" row
//                             // here, we push thm
//                             self.push_call_stack(F::from_canonical_usize(self.depth));
//                             self.push_call_stack(F::from_bool(false));
//                             self.state = TrieBuilderState::Compress;
//                         } else {
//                             assert_eq!(len, 17);
//                             // branch node - need to recurse through children
//                             // push pointer to content onto the stack
//                             self.push_call_stack(F::from_canonical_usize(self.ap));
//                             // push the current range onto the call stack
//                             self.push_call_stack(F::from_canonical_usize(self.lo));
//                             self.push_call_stack(F::from_canonical_usize(self.hi));
//                             // push the current node_id onto the stack
//                             self.push_call_stack(F::from_canonical_usize(self.node_id));
//                             // push the current depth onto the stack
//                             self.push_call_stack(F::from_canonical_usize(self.depth));

//                             // check that the last content entry points to the empty string
//                             assert_eq!(self.rlp_mem[self.ap + 5 + 16], F::ZERO);

//                             self.hi = next_hi;
//                             self.depth += 1;
//                             self.ap = next_item;
//                             self.state = TrieBuilderState::ObserveNode;
//                         }
//                     }
//                 },
//                 TrieBuilderState::Compress => {
//                     // first entry is encoded path
//                     // we'll check it by iteratively incresing the path length and checking that lo / hi stay the same
//                     // unti the whole path has been inclueded
//                     let (lo, hi) = self.next_range(self.lo);
//                     if lo == self.lo && hi == self.hi {
//                         // path is not yet complete
//                         self.depth += 1;
//                         if self.depth == self.get_path_len(self.lo).to_canonical_u64() as usize {
//                             // we've reached the end of the path
//                             // this node is a compressed leaf
//                             // pop old depth off of the stack
//                             let start_depth = self.pop_call_stack();
//                             // push the compressed path len onto the stack
//                             self.push_call_stack(self.get_path_len(self.lo) - start_depth);
//                             self.push_call_stack(F::from_bool(true));
//                             self.state = TrieBuilderState::CheckCompressedPath;
//                         } else {
//                             // continue compressing
//                             self.state = TrieBuilderState::Compress;
//                         }
//                     } else {
//                         // we're done compressing, but we're not at a leaf - it's an extension node
//                         let start_depth = self.pop_call_stack();
//                         // in the stark, we can get this from the "previous" row
//                         // here, we push it
//                         self.push_call_stack(self.get_path_len(self.lo) - start_depth);
//                         self.push_call_stack(F::from_bool(false));
//                         self.state = TrieBuilderState::CheckCompressedPath;
//                     }
//                 },
//                 TrieBuilderState::CheckCompressedPath => {
//                     // in the stark, we can get this from the "previous" row
//                     let is_leaf = self.pop_call_stack().to_canonical_u64() == 1;
//                     let compressed_path_len = self.pop_call_stack().to_canonical_u64() as usize;

//                     // read the first string's entry
//                     let child = self.push_read_rlp_mem().to_canonical_u64() as usize;
//                     let is_list = self.rlp_mem[child + 2].to_canonical_u64() == 1;
//                     let id = self.rlp_mem[child + 3].to_canonical_u64() as usize;
//                     let len = self.rlp_mem[child + 4].to_canonical_u64() as usize;


//                     // check compressed path
//                     let path_top = self.depth + 1 - compressed_path_len;
//                     let compressed_path = &self.sorted_paths[self.lo][path_top..self.depth + 1];
//                     let encoded_path = encode_compressed_path_to_bytes(compressed_path, is_leaf);

//                     // encoded path len in bytes = ceil(compressed path len in nibbles / 2);
//                     assert_eq!(encoded_path.len(), compressed_path_len + 2 / 2);
//                     assert_eq!(len, encoded_path.len());

//                     // check node id
//                     assert_eq!(id, self.node_id);
//                     // check is_list == true
//                     assert_eq!(is_list, false);

//                     // slice check
//                     for b in compressed_path {
//                         assert!(self.rlp_mem[child].to_canonical_u64() == *b as u64);
//                     }

//                     if is_leaf {
//                         // check leaf value
//                         self.state = TrieBuilderState::CheckLeafValue;
//                     } else {
//                         // recurse - we check child hashes after upon return
//                         let (lo, hi) = self.next_range(self.lo);

//                         self.push_call_stack(F::from_canonical_usize(self.ap));
//                         self.push_call_stack(F::from_canonical_usize(self.lo));
//                         self.push_call_stack(F::from_canonical_usize(self.hi));
//                         self.push_call_stack(F::from_canonical_usize(self.node_id));

//                         self.lo = lo;
//                         self.hi = hi;
//                         self.depth += 1;
//                         let next_item = self.rlp_mem[self.ap - 5].to_canonical_u64() as usize;
//                         self.ap = next_item;

//                         self.state = TrieBuilderState::ObserveNode;
//                     }
//                 },
//                 TrieBuilderState::CheckLeafValue => {
//                     // check leaf's value string entry
//                     let child = self.push_read_rlp_mem().to_canonical_u64() as usize;
//                     let is_list = self.rlp_mem[child + 2].to_canonical_u64() == 1;
//                     let len = self.rlp_mem[child + 4].to_canonical_u64() as usize;

//                     // check is_list == false
//                     assert_eq!(is_list, false);

//                     // check len = len of the current path's corresponding leaf value
//                 }
//             }
//         }    
//     }
// }



#[cfg(test)]
mod tests {
    use std::str;
    use std::sync::Arc;

    use anyhow::Result;
    use eth_trie::MemoryDB;
    use eth_trie::{EthTrie, Trie, TrieError};
    use hex::encode;

    use super::*;

    fn print_node_items(items: &[RlpItem]) {
        for item in items {
            let encoded_item = rlp::encode(item);
            let mut hasher = Keccak::v256();
            let mut node_hash = [0u8; 32];
            hasher.update(&encoded_item);
            hasher.finalize(&mut node_hash);
            match item {
                RlpItem::List(items) => {
                    match items.len() {
                        // leaf or extension
                        2 => {
                            let path = items[0].try_as_byte_str().unwrap();
                            let val = items[1].try_as_byte_str().unwrap();
                            println!(
                                "{} | path: \"{}\", val: \"{}\"",
                                encode(node_hash),
                                encode(path),
                                str::from_utf8(&val).unwrap()
                            );
                        }
                        // branch
                        17 => {
                            let children = &items[0..16]
                                .iter()
                                .map(|x| x.try_as_byte_str().unwrap())
                                .collect::<Vec<_>>();
                            let val = items[16].try_as_byte_str().unwrap();
                            let children = children.iter().map(encode).collect::<Vec<_>>();
                            println!(
                                "{} | children: {:?}, val: \"{}\"",
                                encode(node_hash),
                                children,
                                str::from_utf8(&val).unwrap()
                            );
                        }
                        _ => unreachable!(),
                    }
                }
                // all node items should be lists!
                RlpItem::Str(data) => unreachable!(),
            }
        }
    }

    #[test]
    fn test_trie_template_basic() -> Result<()> {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        let leaves = vec![
            b"As I was going down impassive Rivers,".to_vec(),
            b"I no longer felt myself guided by haulers:".to_vec(),
            b"Yelping redskins had taken them as targets".to_vec(),
            b"And had nailed them naked to colored stakes.".to_vec(),
            b"I was indifferent to all crews,".to_vec(),
            b"The bearer of Flemish wheat or English cottons".to_vec(),
            b"When with my haulers this uproar stopped".to_vec(),
            b"The Rivers let me go where I wanted.".to_vec(),
            b"Into the furious lashing of the tides".to_vec(),
            b"More heedless than children's brains the other winters".to_vec(),
            b"I ran! And loosened Peninsulas".to_vec(),
            b"Have not undergone a more triumphant hubbub".to_vec(),
            b"The storm blessed my sea vigils".to_vec(),
            b"Lighter than a cork I danced on the waves".to_vec(),
            b"That are called eternal rollers of victims,".to_vec(),
            b"Ten nights, without missing the stupid eye of the lighthouses!".to_vec(),
        ]
        .into_iter()
        .map(|v| leaf_val(&v))
        .collect::<Vec<_>>();

        for (i, leaf) in leaves.iter().enumerate() {
            let key = rlp_encode_idx(i);
            trie.insert(&key, leaf)?;
        }
        let expected = trie.root_hash()?;

        let mut template = TrieTemplate::from_leaves(&leaves);
        template.compress();
        let (got, items) = template.to_rlp_items(&leaves);

        println!("\n trie items:");
        print_node_items(&items);

        assert_eq!(expected.0, got);

        Ok(())
    }
}
