use super::*;
use rand::random;
use std::ops::BitXor;
use std::convert::TryInto;
use std::io::{self, Write};

type Dset = [State; 256];
//pub type Oracle = FnMut(&[u8]) -> Vec<u8>;

fn init_dset() -> Dset {
    let mut dset: Dset = [ [random::<u8>(); STATE_SIZE]; 256 ];
    for i in 0..256 {
        dset[i][0] = i as u8;
    }
    return dset;
}

fn setup<Oracle>(oracle: &mut Oracle) -> Dset
where Oracle: FnMut(&[u8]) -> Vec<u8> {
    let mut dset = init_dset();
    for m in dset.iter_mut() {
        let tmp = oracle(m);
        *m = tmp.as_slice().try_into().expect("Expected oracle to return size 16 when fed size 16");
    }
    return dset;
}

fn reverse_state(dset: Dset, guess: u8, idx: usize) -> [u8; 256]{
    let mut ret = [0u8; 256];
    for i in 0..256 {
        let mut tmp = dset[i][idx];
        tmp = tmp.bitxor(guess);
        tmp = SBOX_INV[tmp as usize];
        ret[i] = tmp;
    }
    return ret;
}

fn check_guess(rset: [u8; 256]) -> bool {
    let mut res: u8 = 0x00;
    for b in rset.iter() {
        res = res.bitxor(b);
    }
    return res == 0x00;
}

fn guess_byte<Oracle>(oracle: &mut Oracle, idx: usize) -> u8
where Oracle: FnMut(&[u8]) -> Vec<u8> {
    let mut results = [true; 256];
    let mut n_eliminated = 0;
    print!("{} candidates remaining", 256-n_eliminated); io::stdout().flush().unwrap();
    while n_eliminated < 255 {
        //setup is random so no deterministic end condition, could be made deterministic but too lazy to do so
        let dset = setup(oracle);
        for guess in 0..256 {
            if results[guess] {
                let rstate = reverse_state(dset, guess as u8, idx);
                if !check_guess(rstate) {
                    results[guess] = false;
                    n_eliminated += 1;
                    print!("\r{} candidates remaining", 256-n_eliminated); io::stdout().flush().unwrap();
                }
            }
        }
    }
    for b in 0..256 {
        if results[b] {
            return b as u8;
        }
    }
    panic!("should never get here");
}


fn key_expansion_inverse(round_key: [u8; 16], round: usize) ->  [u8; 16] {
    let mut prev_key = [0u8; 16];
    let col1: Word = round_key[0 .. 4].try_into().expect("");
    let col2: Word = round_key[4 .. 8].try_into().expect("");
    let col3: Word = round_key[8 ..12].try_into().expect("");
    let col4: Word = round_key[12..16].try_into().expect("");
    
    prev_key = put_word( xor_word(col3, col4), prev_key, 3  );
    prev_key = put_word( xor_word(col2, col3), prev_key, 2  );
    prev_key = put_word( xor_word(col1, col2), prev_key, 1  );

    let mut tmp: Word = prev_key[12..16].try_into().expect("");
    tmp = rot_word(tmp);
    tmp = sub_word(tmp);
    tmp = xor_word( xor_word(rcon(round), col1), tmp);
    prev_key = put_word(tmp, prev_key, 0);
    prev_key
}

pub fn perform_square<Oracle>(oracle: &mut Oracle) -> [u8; 16]
where Oracle: FnMut(&[u8]) -> Vec<u8> {
    let mut round_key = [0u8 ; 16];
    for b in 0..16 {
        print!("guessing key byte number {}..\n", b);
        round_key[b] = guess_byte(oracle, b);
    }
    for round in (1..=4).rev() {
        round_key = key_expansion_inverse(round_key, round);
    }
    return round_key;
}


#[cfg(test)]
mod test {
    use super::*;

    const key: u128 = 0xdeadbeef;

    fn test_oracle(input: &[u8]) -> Vec<u8> {
        let state: State = input.try_into().expect("this should never show up");
        encrypt_block(state, key, 4).to_vec()
    }

    #[test]
    fn test_reverse_and_guess() {
        let dset = setup(&mut test_oracle);
        let mut aes_key = AES128Key::new(key);
        let round_key = aes_key.get_round_key(4);
        let idx = 5;
        let guess = round_key[idx];

        let rstate = reverse_state(dset, guess, idx);
        assert!(check_guess(rstate));
    }

    #[test]
    fn test_key_expansion_inverse() {
        let mut aes_key = AES128Key::new(key);

        for r in 1..5 {
            assert_eq!( key_expansion_inverse(aes_key.get_round_key(r), r), aes_key.get_round_key(r-1) );
        }

    }

    #[test]
    fn test_square() {
        let mut aes_key = AES128Key::new(key);
        let round_key = aes_key.get_round_key(0);

        assert_eq!(perform_square(&mut test_oracle), round_key);
    }
}