use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2_util::log2_ceil;
use rlp::encode;
use tiny_keccak::{Hasher, Keccak};

use crate::starky2lib::{
    rlp::generation::{compute_str_prefix, RlpItem, RlpStarkGenerator},
    stack::generation::StackOp,
};
use super::layout::*;

pub struct IdxKeyedTrieGenerator<F: RichField> {
    trace: Vec<IdxKeyedTrieRow<F>>,
    state: IdxKeyedTrieState,
}

enum IdxKeyedTrieState {
    // PHASE 1: GENERATE TEMPLATE

    // the state machine starts in this state
    // set pc to 1, pointing to the root node in the template. then, if `path_op_id` is 0, then transition to PHASE_2_OBSERVE_ENTRY.
    // otherwise, increment `path_op_id` and pop the `op_id` from the encoded path stack, check they match, pop the path length, and transition to PHASE_1_INIT_ENTRY if it's the first row, PHASE_1_OBSERVE_ENTRY otherwise
    PHASE_1_NEXT_ENTRY,

    // initialize an entry.
    // if is_last_nibble is set, then we make a DefLeaf entry whose `plen = 0, path = "", value_idx = path_op_id` and transition to PHASE_1_NEXT_PATH
    // otherwise, then we make a MaybeLeaf whose `plen = 0, path = "", has_val = 0, value_idx = NULL, num_children = 0, children = [NULL; 16]` and transition to PHASE_1_RECURSE
    // then we increment node idx and jump to PHASE_1_RECURSE
    PHASE_1_INIT_ENTRY,

    // observe an entry and/or update it
    // read the entry's metadata.
    // if the `is_last_nibble` is set and the entry we're looking at is a branch, then set `has_val = 1. val_idx = path_op_id` and transition to PHASE_1_NEXT_PATH
    // otherwise, if then `is_last_nibble` is false because we will never go to a DefLeaf twice during this phase
    PHASE_1_OBSERVE_ENTRY,

    // if `is_hi_nibble` is set, then "pop" one byte from the enhcoded path, set `hi_nibble` and `lo_nibble` accordingly, then set the child pointer for `hi_nibble` to sp and increment num_children if it's currently NULL
    // otherwise, set the child pointer for `lo_nibble` to sp and increment `num_children` if its currently NULL
    // toggle `is_hi_nibble`
    // Then, jump to sp and transition to PHASE_1_INIT_ENTRY if the child pointer was NULL, otherwise jump to the child pointer and transition to PHASE_1_OBSERVE_ENTRY
    PHASE_1_RECURSE,


    // PHASE 2: GENERATE TEMPLATE

    // let `compress` = `1` if the current entry is not a DefLeaf AND `num_children == 1` AND `has_val == 0`
    // if `compress`, then:
    //   push pc onto the stack
    //   set `pp` to point to the plen field of the current entry. This sets the "compressed parent" to which the path is accumulated and child is reset
    //   set `compressed_child_ptr` = the one non-null child pointer. Set non-deternimistically, and guaranteed to be the only one due to the manner in which
    //   we constructed the template
    //   transition to PHASE_2_COMPRESS
    // otherwise if the current entry is not a leaf (entry is not DefLeaf and kind is not set to `00`):
    //   initialize a child counter to 0
    //   transition to PHASE_2_RECURSE_SETUP
    // otherwise (in the case of a leaf):
    //   transition to PHASE_2_WRITE_ENTRY
    PHASE_2_OBSERVE_ENTRY,

    // if the current entry is a `DefLeaf`:
    //   use pp to calculate the offset of the parent's tag. Then, set the tag to `00`, indicating it's now a leaf
    //   use the same method to set the paren'ts `has_val` to 1 and `val_idx` to the current leaf entry's `val_idx`.
    //   transition to PHASE_2_RETURN
    // otherwise:
    //   let `compress` = `1` if the current entry is not a leaf AND `num_children == 1` AND `has_val == 0`
    //   let `child_nibble` = the nibble of the one non-null child pointer. Set non-deternimistically, and guaranteed to be the only one due to the manner in which the we constructed the template
    //   `[pp] += 1`
    //   `path.append(child_nibble)`
    //   if `compress = 0`, then 
    //     [compressed_child_ptr] =  pc (set the compressed parent's child pointer to the current entry)
    //     calculate the compressed parents pc using `pp` and jump all the way back to the parent
    //     initialize child counter to 0
    //     transition to PHASE_2_RECURSE_SETUP
    //   otherise:
    //     set pc to the `child_nibble`th child pointer in the entry
    //     stay at PHASE_2_COMPRESS
    PHASE_2_COMPRESS,

    // push the counter to the stack
    // then push the nibble for the next non-null child pointer onto the stack. The prover chooses this non-deterministically, and the ordering / deduplication is checked via a range check.
    // increment the counter.
    // 
    // then, if the counter = num_children, transition to PHASE_2_RECURSE
    // otherwise, stay at PHASE_2_RECURSE_SETUP
    PHASE_2_RECURSE_SETUP,

    // pop a child pointer off of the stack.
    // push the current pc onto the stack
    // increment depth by 1
    // set pc to the child pointer and transition to PHASE_2_OBSERVE_ENTRY
    PHASE_2_RECURSE,

    // pop the old pc off of the stack
    // pop the counter off of the stack
    // set pc to the old pc
    // decrement depth by 1
    // then,
    //   if both the counter and depth are 0, then transition to HALT
    //   otherwise, if the counter is 0, then transition to PHASE_2_WRITE_ENTRY
    //   otherwise, transition to PHASE_2_RECURSE
    PHASE_2_RETURN,

    // read the medata of the current template node and write out the outer RLP list entry for it
    // write leaf list entry metadata according to the node kind;
    //   leaf: 2 elements
    //   extension: 2 elements
    //   branch: 17 elements
    // advance ep to start of the content
    // push ep to the stack
    // advance ep to after the end of the content
    // if the node is a leaf or extension, then set counter to 0 and transition to PHASE_2_WRITE_ENCODED_PATH,
    // otherwise, transition to PHASE_2_W
    PHASE_2_WRITE_ENTRY,

    // calculate the prefix to apply to the path given plen and the node kind.
    // write the string RLP entry metadata given the prefix and path len
    // write the `counter`th byte of the path into the content
    // increment counter 
    // if counter = path_len in bytes and the current node is a leaf, then transition to PHASE_2_WRITE_VALUE
    // othrewise, if counter == path_len in bytes then set counter = 1 transition to PHASE_2_WRITE_HASH
    PHASE_2_WRITE_ENCODED_PATH,

    //! how do we get child's op ids???
    PHASE_2_WRITE_HASH,

    HALT,
}

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

// if val < 32 bytes, pad it with zeroes up to 32 bytes.
// this needed because this trie impl only works with values >= 32 bytes
pub fn leaf_val(val: &[u8]) -> Vec<u8> {
    let mut val = val.to_vec();
    if val.len() < 32 {
        val.resize(32, 0);
    }
    val
}

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
