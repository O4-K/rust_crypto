mod aes;


use aes::aes128::square;
use std::net::TcpStream;
use std::io::*;
use hex;
use std::str::from_utf8;

fn main() {
    let mut stream = TcpStream::connect("challenge01.root-me.org:51039").expect("aaaa");
    let mut buf = [0; 512];
    stream.read(&mut buf).expect("aaa");
    println!("{}", from_utf8(&buf).expect("") );
    stream.read(&mut buf).expect("aaa");
    println!("{}", from_utf8(&buf).expect("") );

    let mut oracle = |input: &[u8]| -> Vec<u8> {
        let cmd = format!( "e {}\n", hex::encode(input).as_str() );
        stream.write(cmd.as_bytes()).unwrap();
        stream.flush().unwrap();
        let n_read = stream.read(&mut buf).unwrap();
        return hex::decode(&buf[0..32]).expect("");
    };
    let key = square::perform_square(&mut oracle);
    let cmd = format!( "c {}\n", hex::encode(key).as_str() );
    stream.write(cmd.as_bytes()).unwrap();
    stream.read(&mut buf).unwrap();
    println!("{}", from_utf8(&buf).expect("") );
}   

