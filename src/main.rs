extern crate ski;
extern crate tokio;
extern crate tokio_tun;
extern crate async_trait;
extern crate sqlite;
#[macro_use]
extern crate clap;

pub mod error;
pub mod routing;

use std::io;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::Mutex;
use tokio::time::{Duration, self};

// use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio_tun::{Tun, TunBuilder};

use async_trait::async_trait;

use ski::coding::{Encodable, Decodable};

use clap::App;

type Shared<T> = Arc<T>;

#[allow(dead_code)]
fn xf_identity(slice: &[u8]) -> io::Result<Vec<u8>> { Ok(Vec::from(slice)) }

#[async_trait]
trait Transput: Sync + Send {
    async fn tx(&self, buffer: &[u8]) -> io::Result<()>;
    async fn rx(&self, buffer: &mut [u8]) -> io::Result<usize>;
}

struct BoundUdpSocket {
    pub addr: Mutex<SocketAddr>,
    pub update: bool,
    pub sock: Shared<UdpSocket>,
}

#[async_trait]
impl Transput for BoundUdpSocket {
    async fn tx(&self, buffer: &[u8]) -> io::Result<()> {
        if let Err(e) = self.sock.send_to(buffer, &*self.addr.lock().await).await {
            println!("udp send error: {:?}", e);
        }
        Ok(())
    }
    async fn rx(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.sock.recv_from(buffer).await {
                Ok((bytes, peer)) => {
                    if self.update {
                        *self.addr.lock().await = peer;
                        return Ok(bytes);
                    } else {
                        if peer == *self.addr.lock().await { return Ok(bytes); }
                    }
                },
                Err(e) => {
                    println!("udp recv error: {:?}", e);
                }
            }
        }
    }
}

#[async_trait]
impl Transput for Tun {
    async fn tx(&self, buffer: &[u8]) -> io::Result<()> {
        if let Err(e) = self.send(buffer).await {
            println!("tun send error: {:?}", e);
        }
        Ok(())
    }
    async fn rx(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.recv(buffer).await {
                Ok(sz) => { return Ok(sz); },
                Err(e) => { println!("tun recv error: {:?}", e); },
            }
        }
    }
}

async fn transfer<F>(
    src: Shared<dyn Transput>,
    dst: Shared<dyn Transput>,
    mut xfrm: F,
    bufsize: usize,
    ident: &'static str
) -> io::Result<()> where
    F: FnMut(&[u8]) -> io::Result<Vec<u8>>,
{
    let mut rx_buffer: Vec<u8> = vec![0u8; bufsize];

    loop {
        let bytes = src.rx(&mut rx_buffer).await?;
        println!("{}: {:?}", ident, bytes);
        match xfrm(&rx_buffer[..bytes]) {
            Ok(out) => { dst.tx(&out).await?; },
            Err(e) => println!("xfer err: {:?}", e),
        }
    }
}

const BYTES: usize = 65536usize;

async fn tokio_main() -> io::Result<()> {
    let yaml = load_yaml!("args.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let key_urn = matches.value_of("key").unwrap();
    let key = ski::sym::Key::decode(
        &ski::coding::CodedObject::from_urn(&key_urn).unwrap()
    ).unwrap();

    let (udp, tun) = (
        UdpSocket::bind(matches.value_of("bind").unwrap_or("0.0.0.0:0").parse::<SocketAddr>().unwrap()).await?,
        TunBuilder::new()
            .name(matches.value_of("intf").unwrap_or("ski"))
            .packet_info(false)
            .try_build().unwrap(),
    );

    let udp = Shared::new(udp);

    let (a, b): (Shared<dyn Transput>, Shared<dyn Transput>) = (
        Shared::new(tun),
        Shared::new(BoundUdpSocket {
            sock: udp.clone(),
            addr: Mutex::new(matches.value_of("peer").unwrap().parse().unwrap()),
            update: matches.is_present("roam"),
        }),
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

    let a2b = tokio::spawn(transfer(a.clone(), b.clone(), encrypt, BYTES, "from_udp"));
    let b2a = tokio::spawn(transfer(b.clone(), a.clone(), decrypt, BYTES, "from_tun"));

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
