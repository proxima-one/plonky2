// Read a word from the current account's storage trie.
//
// Pre stack: slot, retdest
// Post stack: value

global storage_read:
    // stack: slot, retdest
    %stack (slot) -> (slot, after_storage_read)
    %slot_to_storage_key
    // stack: storage_key, after_storage_read, retdest
    PUSH 64 // storage_key has 64 nibbles
    %current_storage_trie
    // stack: storage_root_ptr, 64, storage_key, after_storage_read, retdest
    %jump(mpt_read)

after_storage_read:
    // stack: value_ptr, retdest
    DUP1 %jumpi(storage_key_exists)

    // Storage key not found; return default value of 0.
    %stack (value_ptr, retdest) -> (retdest, 0)
    JUMP

storage_key_exists:
    // stack: value_ptr, retdest
    %mload_trie_data // TODO: If we end up not using value pointers in storage tries, remove this.
    SWAP1
    JUMP
