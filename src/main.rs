extern crate ski;
extern crate tokio;

use std::io;
use std::sync::Arc;
use std::net::SocketAddr;

// use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use ski::coding::{Encodable, Decodable};

type Shared<T> = Arc<T>;

#[allow(dead_code)]
fn xf_identity(slice: &[u8]) -> io::Result<Vec<u8>> { Ok(Vec::from(slice)) }

async fn transfer<F>(
    src: Shared<UdpSocket>,
    dst: Shared<UdpSocket>,
    mut xfrm: F,
    bufsize: usize,
) -> io::Result<()> where
    F: FnMut(&[u8]) -> io::Result<Vec<u8>>,
{
    let mut rx_buffer: Vec<u8> = vec![0u8; bufsize];

    loop {
        let (bytes, peer) = src.recv_from(&mut rx_buffer).await?;
        match xfrm(&rx_buffer[..bytes]) {
            Ok(out) => { dst.send_to(&out, &peer).await?; },
            Err(e) => println!("send err: {:?}", e),
        }
    }
}

const BYTES: usize = 65536usize;

async fn tokio_main() -> io::Result<()> {
    let key_urn = std::env::args().nth(1).unwrap();
    let key = ski::sym::Key::decode(
        &ski::coding::CodedObject::from_urn(&key_urn).unwrap()
    ).unwrap();

    let (a, b) = (
        Shared::new(UdpSocket::bind("127.0.0.1:9001".parse::<SocketAddr>().unwrap()).await?),
        Shared::new(UdpSocket::bind("127.0.0.1:9002".parse::<SocketAddr>().unwrap()).await?),
    );

    let encrypt = {
        let key = key.clone();
        move |a: &[u8]| {
            let cipher = key.cipher();
            let ed = cipher.encipher(a);
            ed.encode().as_binary().map_err(|_| io::Error::new(io::ErrorKind::Other, "encode failed"))
        }
    };
    let decrypt = {
        let key = key.clone();
        move |a: &[u8]| {
            let ed = ski::sym::EncipheredData::decode(
                &ski::coding::CodedObject::from_binary(a).map_err(|_| io::Error::new(io::ErrorKind::Other, "decode failed"))?
            ).map_err(|_| io::Error::new(io::ErrorKind::Other, "decode as ED failed"))?;
            let cipher = key.cipher_for_data(&ed);
            Ok(cipher.decipher(&ed))
        }
    };

    let a2b = tokio::spawn(transfer(a.clone(), b.clone(), encrypt, BYTES));
    let b2a = tokio::spawn(transfer(b.clone(), a.clone(), decrypt, BYTES));

    Ok(tokio::select! {
        _ = a2b => (),
        _ = b2a => (),
    })
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(tokio_main())
        .unwrap();
}
