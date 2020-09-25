mod aes;
mod aes_const;

use aes::aes128::encrypt_str;

fn main() {
    let key : u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
    let msg = "theblockbreakers";

    let ret = encrypt_str(&msg, key);

    println!("{:x?}", ret);
 

}

