extern crate ski;
extern crate mio;

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, AddrParseError};

use mio::{Token, Poll, Events, Interest};
use mio::net::UdpSocket;

use ski::coding::{Encodable, Decodable};

const RECV: Token = Token(0);
const SEND: Token = Token(1);

#[derive(Debug)]
enum Error {
    IO(io::Error),
    Addr(AddrParseError),
    SKI(ski::error::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<AddrParseError> for Error {
    fn from(e: AddrParseError) -> Self {
        Self::Addr(e)
    }
}

impl From<ski::error::Error> for Error {
    fn from(e: ski::error::Error) -> Self {
        Self::SKI(e)
    }
}

fn main() -> Result<(), Error> {
    let key_urn = std::env::args().nth(1).unwrap();
    let key = ski::sym::Key::decode(
        &ski::coding::CodedObject::from_urn(&key_urn)?
    )?;
    println!("{:?}", key);

    let mut recv_socket = UdpSocket::bind("127.0.0.1:9001".parse()?)?;
    let mut send_socket = UdpSocket::bind("127.0.0.1:9002".parse()?)?;

    let mut poll = Poll::new()?;

    poll.registry().register(&mut recv_socket, RECV, Interest::READABLE)?;
    poll.registry().register(&mut send_socket, SEND, Interest::READABLE)?;

    let mut sq: VecDeque<(SocketAddr, Vec<u8>)> = VecDeque::new();
    let mut rq: VecDeque<(SocketAddr, Vec<u8>)> = VecDeque::new();

    let mut events = Events::with_capacity(1024);
    let mut buffer = [0u8; 65536];

    loop {
        poll.poll(&mut events, None)?;
        for ev in events.iter() {
            match ev.token() {
                RECV => {
                    if ev.is_writable() {
                        while rq.len() > 0 {
                            let (addr, buf) = rq.pop_front().unwrap();
                            match recv_socket.send_to(&buf, addr) {
                                Ok(bt) => println!("RQ: sent {}", bt),
                                Err(e) => {
                                    if e.kind() == io::ErrorKind::WouldBlock {
                                        println!("RQ: throttle");
                                        break;
                                    }
                                    println!("RQ: send unhandled error: {:?}", e);
                                },
                            }
                        }
                        let mut int = Interest::READABLE;
                        if rq.len() > 0 {
                            int |= Interest::WRITABLE;
                        }
                        poll.registry().reregister(&mut recv_socket, RECV, int)?;
                    }
                    if ev.is_readable() {
                        loop {
                            match recv_socket.recv_from(&mut buffer) {
                                Ok((bt, addr)) => {
                                    let cipher = key.cipher();
                                    let data = cipher.encipher(&buffer[..bt]);
                                    sq.push_back((addr, data.encode().as_binary()?));
                                    println!("RQ: received {}", bt);
                                },
                                Err(e) => {
                                    if e.kind() == io::ErrorKind::WouldBlock {
                                        break;
                                    }
                                    println!("RQ: recv unhandled error: {:?}", e);
                                },
                            }
                        }
                        if sq.len() > 0 {
                            poll.registry().reregister(&mut send_socket, SEND, Interest::READABLE | Interest::WRITABLE)?;
                        }
                    }
                },
                SEND => {
                    if ev.is_writable() {
                        while sq.len() > 0 {
                            let (addr, buf) = sq.pop_front().unwrap();
                            match send_socket.send_to(&buf, addr) {
                                Ok(bt) => println!("SQ: sent {}", bt),
                                Err(e) => {
                                    if e.kind() == io::ErrorKind::WouldBlock {
                                        println!("SQ: throttle");
                                        break;
                                    }
                                    println!("SQ: send unhandled error: {:?}", e);
                                },
                            }
                        }
                        let mut int = Interest::READABLE;
                        if rq.len() > 0 {
                            int |= Interest::WRITABLE;
                        }
                        poll.registry().reregister(&mut send_socket, SEND, int)?;
                    }
                    if ev.is_readable() {
                        loop {
                            match send_socket.recv_from(&mut buffer) {
                                Ok((bt, addr)) => {
                                    let ed = ski::sym::EncipheredData::decode(
                                        &ski::coding::CodedObject::from_binary(&buffer[..bt])?
                                    )?;
                                    let cipher = key.cipher_for_data(&ed);
                                    let data = cipher.decipher(&ed);
                                    rq.push_back((addr, data));
                                    println!("SQ: received {}", bt);
                                },
                                Err(e) => {
                                    if e.kind() == io::ErrorKind::WouldBlock {
                                        break;
                                    }
                                    println!("SQ: recv unhandled error: {:?}", e);
                                },
                            }
                        }
                        if rq.len() > 0 {
                            poll.registry().reregister(&mut recv_socket, RECV, Interest::READABLE | Interest::WRITABLE)?;
                        }
                    }
                },
                _ => unreachable!(),
            }
        }
    }
}
