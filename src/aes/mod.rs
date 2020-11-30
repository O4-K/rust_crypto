mod aes_const;

use std::convert::TryInto;
use std::ops::BitXor;
use std::iter::Iterator;
use aes_const::*;


const WORD_SIZE:  usize  =  4;
const STATE_SIZE: usize  = 16;

type Word  = [u8;  WORD_SIZE];
type State = [u8; STATE_SIZE];

pub mod aes128 {
    pub mod square;
    pub mod dfa;
    
    use super::*;
    
    const N_ROUNDS: usize = 10;
    
    fn rot_word(word: Word) -> Word {
        return [word[1], word[2], word[3], word[0]];
    }
    
    fn sub_word(word: Word) -> Word {
        let mut ret: Word = [0; 4];
        let mut i = 0;
        
        while i < 4 {
            ret[i] = SBOX[word[i] as usize];
            i+=1;
        }
    
        return ret;
    }
    
    fn rcon( i: usize ) -> Word {
        return [ RCON[i as usize], 0x00, 0x00, 0x00 ];
    }
    
    fn xor_word(x: Word, y: Word) -> Word {
        let mut ret = [0; 4];
        for i in 0..4 {
            ret[i] = x[i].bitxor(y[i]);
        }
        return ret;
    }
    
    fn split_u128(x: u128) -> State {
        let mut ret: State = [0x00; 16];
        let mut tmp = x;
        for i in 0..16 {
            ret[15-i] = tmp as u8;
            tmp = tmp >> 8;
        }
        return ret;
    }
    
    fn merge_u128(x: State) -> u128 {
        let mut ret: u128 = 0;
        for i in 0..16 {
            let tmp = x[15-i] as u128;
            ret += tmp << 8*i;
        }
        return ret;
    }
    
    fn idx(icol: usize, irow: usize) -> usize {
        return WORD_SIZE*icol + irow;
    }
    
    fn init_state() -> State {
        return [0; 16];
    }
    
    fn put_word(word: Word, state: State, icol: usize) -> State {
        let mut ret = state;
        for irow in 0..WORD_SIZE {
            ret[idx(icol, irow)] = word[irow];
        }
        return ret;
    }
    
    fn sub_bytes(state: State) -> State {
        let mut ret: State = [0; 16];
        let mut i = 0;
        
        while i < 16 {
            ret[i] = SBOX[state[i] as usize];
            i+=1;
        }
        return ret;
    }

    fn sub_bytes_inverse(state: State) -> State {
        let mut ret: State = [0; 16];
        let mut i = 0;
        
        while i < 16 {
            ret[i] = SBOX_INV[state[i] as usize];
            i+=1;
        }
        return ret;
    }
    
    fn shift_rows(state: State) -> State {
        let mut ret: State = [0; 16];
        for irow in 0..4 {
            for icol in 0..4 {
                ret[idx(icol, irow)] = state[idx( (icol+irow) % 4, irow)];
            }
        }
        return ret;
    }

    fn shift_rows_inverse(state: State) -> State {
        let mut ret: State = [0; 16];
        for irow in 0..4 {
            for icol in 0..4 {
                ret[idx(icol, irow)] = state[idx( (icol+4-irow) % 4, irow)];
            }
        }
        return ret;
    }
    
    fn mix_columns(state: State) -> State {
        let mut ret = init_state();
        for icol in 0..4 {
            let mut tmp: Word = [0; 4];
            let (a0, a1, a2, a3) = ( state[idx(icol, 0)], state[idx(icol, 1)], state[idx(icol, 2)], state[idx(icol, 3)] );
            let (a0s, a1s, a2s, a3s) = ( a0 as usize, a1 as usize, a2 as usize, a3 as usize );
            tmp[0] = MUL2[a0s].bitxor(MUL3[a1s]).bitxor(a2).bitxor(a3) as u8;
            tmp[1] = a0.bitxor(MUL2[a1s]).bitxor(MUL3[a2s]).bitxor(a3) as u8;
            tmp[2] = a0.bitxor(a1).bitxor(MUL2[a2s]).bitxor(MUL3[a3s]) as u8;
            tmp[3] = MUL3[a0s].bitxor(a1).bitxor(a2).bitxor(MUL2[a3s]) as u8;
            ret = put_word(tmp, ret, icol);
        }
        return ret;
    }

    fn mix_columns_inverse(state: State) -> State {
        let mut ret = init_state();
        for icol in 0..4 {
            let mut tmp: Word = [0; 4];
            let (a0, a1, a2, a3) = ( state[idx(icol, 0)], state[idx(icol, 1)], state[idx(icol, 2)], state[idx(icol, 3)] );
            let (a0s, a1s, a2s, a3s) = ( a0 as usize, a1 as usize, a2 as usize, a3 as usize );
            tmp[0] = MUL14[a0s].bitxor(MUL11[a1s]).bitxor(MUL13[a2s]).bitxor(MUL9[a3s]) as u8;
            tmp[1] = MUL9[a0s].bitxor(MUL14[a1s]).bitxor(MUL11[a2s]).bitxor(MUL13[a3s]) as u8;
            tmp[2] = MUL13[a0s].bitxor(MUL9[a1s]).bitxor(MUL14[a2s]).bitxor(MUL11[a3s]) as u8;
            tmp[3] = MUL11[a0s].bitxor(MUL13[a1s]).bitxor(MUL9[a2s]).bitxor(MUL14[a3s]) as u8;
            ret = put_word(tmp, ret, icol);
        }
        return ret;
    }
    
    fn add_round_key(state: State, round_key: State) -> State {
        let mut ret = init_state();
        for i in 0..STATE_SIZE {
            ret[i] = state[i].bitxor(round_key[i]);
        }
        return ret;
    }

    pub struct AES128Key {
        key: u128,
        round: u8,
        round_keys: Vec<State>,
    }
    
    impl AES128Key {
        pub fn new(key: u128) -> AES128Key {
            AES128Key{
                key: key,
                round: 0,
                round_keys: vec![split_u128(key)],
            }
        }

        fn compute_next_round_key(cur_round_key: State, round: usize) -> State {
            let mut next_round_key: State = [0; STATE_SIZE];

            let mut word: Word = cur_round_key[12..16].try_into().expect("blabla");
            word = rot_word(word);
            word = sub_word(word);
            word = xor_word(word, cur_round_key[0..4].try_into().expect("blabla"));
            word = xor_word(word, rcon(round));

            for i in 0..4 {
                next_round_key[i] = word[i];
            } 

            for icol in 1..4 {
                let col: Word = cur_round_key[icol*4..(icol+1)*4].try_into().expect("blabla");
                word = xor_word(word, col);
                for i in 0..4 {
                    next_round_key[idx(icol, i)] = word[i];
                }
            }
            return next_round_key;
        }
    
        pub fn get_round_key(&mut self, round: usize) -> State {
            let l = self.round_keys.len();
            if l > round {
                return self.round_keys[round];
            } else {
                let mut rkey = self.round_keys[l-1];
                for r in l..round+1 {
                    rkey = AES128Key::compute_next_round_key(rkey, r);
                    self.round_keys.push(rkey);
                }
                return rkey;
            }
        }
    }

    pub fn print_state(state: State) {
        for irow in 0..4 {
            for icol in 0..4 {
               print!("{:#04x} ", state[idx(icol, irow)]); 
            }
            print!("\n");
        }
    }

    fn encrypt_block(block: State, key: u128, n_rounds: usize) -> State {
        let mut ret = block;
        let mut key = AES128Key::new(key);
        
        //pre-whitening
        ret = add_round_key(ret, key.get_round_key(0));

        //rounds
        for round in 1..n_rounds {
            ret = sub_bytes(ret);
            ret = shift_rows(ret);
            ret = mix_columns(ret);
            ret = add_round_key(ret, key.get_round_key(round));
        }

        //last round
        ret = sub_bytes(ret);
        ret = shift_rows(ret);
        ret = add_round_key(ret, key.get_round_key(n_rounds));

        return ret;
    }

    fn decrypt_block(block: State, key: u128, n_rounds: usize) -> State {
        let mut ret = block;
        let mut key = AES128Key::new(key);
        
        //last round
        ret = add_round_key(ret, key.get_round_key(n_rounds));
        ret = shift_rows_inverse(ret);
        ret = sub_bytes_inverse(ret);

        //rounds
        for round in (1..n_rounds).rev() {            
            ret = add_round_key(ret, key.get_round_key(round));
            ret = mix_columns_inverse(ret);
            ret = shift_rows_inverse(ret);
            ret = sub_bytes_inverse(ret);
        }

        //pre-whitening
        ret = add_round_key(ret, key.get_round_key(0));


        return ret;
    }

    fn encrypt_bytes_iter(iter: impl Iterator<Item=u8>, key: u128) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        let mut state = init_state();

        let mut n = 0;
        for b in iter {
            // println!("{:#04x}",b);
            state[n] = b;
            n+=1;

            if n == STATE_SIZE {
                let e_state = encrypt_block(state, key, N_ROUNDS); //note: computes round keys for each block 
                    // -> should save round keys in AES128Key and have encrypt_block take a AES128key instead of u128
                ret.extend_from_slice(&e_state);
                n = 0;
                state = init_state();
            }
        }
        //last block (zero padded)
        if n != 0 {
            let e_state = encrypt_block(state, key, N_ROUNDS);
            ret.extend_from_slice(&e_state);
        }
        
        return ret;
    }

    pub fn encrypt_bytes(text: &[u8], key: u128) -> Vec<u8> {
        return encrypt_bytes_iter(text.iter().cloned(), key);
    }

    /* zero padded & ECB */
    pub fn encrypt_str(text: &str, key: u128) -> Vec<u8> {
        return encrypt_bytes_iter(text.bytes(), key);
    }

    #[cfg(test)]
    mod test {

        use super::*;

        #[test]
        fn test_sub_bytes() {
            let s: State = [
                0x19, 0x3d, 0xe3, 0xbe,
                0xa0, 0xf4, 0xe2, 0x2b,
                0x9a, 0xc6, 0x8d, 0x2a,
                0xe9, 0xf8, 0x48, 0x08,
            ];

            let r: State = [
                0xd4, 0x27, 0x11, 0xae,
                0xe0, 0xbf, 0x98, 0xf1,
                0xb8, 0xb4, 0x5d, 0xe5,
                0x1e, 0x41, 0x52, 0x30,  
            ];

            assert_eq!(sub_bytes(s), r);
        }

        #[test]
        fn test_shift_rows() {
            let s: State = [
                0xd4, 0x27, 0x11, 0xae,
                0xe0, 0xbf, 0x98, 0xf1,
                0xb8, 0xb4, 0x5d, 0xe5,
                0x1e, 0x41, 0x52, 0x30,  
            ];

            let r: State = [
                0xd4, 0xbf, 0x5d, 0x30,
                0xe0, 0xb4, 0x52, 0xae,
                0xb8, 0x41, 0x11, 0xf1,
                0x1e, 0x27, 0x98, 0xe5,
            ];

            assert_eq!(shift_rows(s), r);
        }

        #[test]
        fn test_mix_columns() {
            let s: State = [
                0xd4, 0xbf, 0x5d, 0x30,
                0xe0, 0xb4, 0x52, 0xae,
                0xb8, 0x41, 0x11, 0xf1,
                0x1e, 0x27, 0x98, 0xe5,
            ];

            let r: State = [
                0x04, 0x66, 0x81, 0xe5,
                0xe0, 0xcb, 0x19, 0x9a,
                0x48, 0xf8, 0xd3, 0x7a,
                0x28, 0x06, 0x26, 0x4c,
            ];

            assert_eq!(mix_columns(s), r);
        }

        #[test]
        fn test_add_round_key () {
            let s: State = [
                0x04, 0x66, 0x81, 0xe5,
                0xe0, 0xcb, 0x19, 0x9a,
                0x48, 0xf8, 0xd3, 0x7a,
                0x28, 0x06, 0x26, 0x4c,
            ];

            let k: State = [
                0xa0, 0xfa, 0xfe, 0x17,
                0x88, 0x54, 0x2c, 0xb1,
                0x23, 0xa3, 0x39, 0x39,
                0x2a, 0x6c, 0x76, 0x05,
            ];

            let r: State = [
                0xa4, 0x9c, 0x7f, 0xf2,
                0x68, 0x9f, 0x35, 0x2b,
                0x6b, 0x5b, 0xea, 0x43,
                0x02, 0x6a, 0x50, 0x49,
            ];

            assert_eq!(add_round_key(s, k), r);
        }

        #[test]
        fn test_encrypt_block () {
            let input: State = [
                0x32, 0x43, 0xf6, 0xa8,
                0x88, 0x5a, 0x30, 0x8d,
                0x31, 0x31, 0x98, 0xa2,
                0xe0, 0x37, 0x07, 0x34,
            ];

            let key: u128 =  0x2b7e151628aed2a6abf7158809cf4f3c;

            let output: State = [
                0x39, 0x25, 0x84, 0x1d,
                0x02, 0xdc, 0x09, 0xfb,
                0xdc, 0x11, 0x85, 0x97,
                0x19, 0x6a, 0x0b, 0x32,
            ];

            assert_eq!(encrypt_block(input, key, 10), output);
        }

        #[test]
        fn test_encrypt_decrypt_block() {
            let input: State = [
                0x32, 0x43, 0xf6, 0xa8,
                0x88, 0x5a, 0x30, 0x8d,
                0x31, 0x31, 0x98, 0xa2,
                0xe0, 0x37, 0x07, 0x34,
            ];
            let key: u128 =  0x2b7e151628aed2a6abf7158809cf4f3c;

            assert_eq!( decrypt_block(encrypt_block(input, key, 10), key, 10), input );
        }

    }
    
}