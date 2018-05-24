use futures::{Async, AsyncSink, Future, Poll, Sink, Stream, sync::mpsc::{self, Receiver, Sender}};

use super::{QuicError, QuicResult};
use conn_state::ConnectionState;
use crypto::Secret;
use packet::{LongType, Packet};
use parameters::ServerTransportParameters;
use tls;
use types::ConnectionId;

use std::collections::{HashMap, hash_map::Entry};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::{self, net::UdpSocket};
use tokio::executor::Executor;

pub struct Server {
    socket: UdpSocket,
    tls_config: Arc<tls::ServerConfig>,
    in_buf: Vec<u8>,
    connections: HashMap<ConnectionId, Sender<Vec<u8>>>,
    send_queue: (
        Sender<(SocketAddr, Vec<u8>)>,
        Receiver<(SocketAddr, Vec<u8>)>,
    ),
}

impl Server {
    pub fn new(ip: &str, port: u16, tls_config: tls::ServerConfig) -> QuicResult<Self> {
        let addr = (ip, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| QuicError::General("no address found for host".into()))?;
        Ok(Server {
            socket: UdpSocket::bind(&addr)?,
            tls_config: Arc::new(tls_config),
            in_buf: vec![0u8; 65536],
            connections: HashMap::new(),
            send_queue: mpsc::channel(5),
        })
    }

    pub fn run(&mut self) -> QuicResult<()> {
        self.wait()
    }
}

impl Future for Server {
    type Item = ();
    type Error = QuicError;

    fn poll(&mut self) -> Poll<(), QuicError> {
        loop {
            let connections = &mut self.connections;
            let (len, addr) = try_ready!(self.socket.poll_recv_from(&mut self.in_buf));

            let cid = {
                let partial = Packet::start_decode(&mut self.in_buf[..len]);
                debug!("incoming packet: {:?} {:?}", addr, partial.header);
                let dst_cid = partial.dst_cid();
                if partial.header.ptype() == Some(LongType::Initial) {
                    let mut state = ConnectionState::new(
                        tls::server_session(
                            &self.tls_config,
                            &ServerTransportParameters::default(),
                        ),
                        Some(Secret::Handshake(dst_cid)),
                    );

                    let cid = state.pick_unused_cid(|cid| connections.contains_key(&cid));
                    let (recv_tx, recv_rx) = mpsc::channel(5);
                    tokio::executor::DefaultExecutor::current().spawn(Box::new(Connection::new(
                        addr,
                        state,
                        self.send_queue.0.clone(),
                        recv_rx,
                    )));
                    connections.insert(cid, recv_tx);
                    cid
                } else {
                    dst_cid
                }
            };

            let msg = self.in_buf[..len].to_vec();
            match connections.entry(cid) {
                Entry::Occupied(mut inner) => {
                    let mut sink = inner.get_mut();
                    match sink.start_send(msg) {
                        Ok(AsyncSink::Ready) => {}
                        Ok(AsyncSink::NotReady(msg)) => error!("discarding message: {:?}", msg),
                        Err(e) => error!("error passing on message: {:?}", e),
                    }
                    match sink.poll_complete() {
                        Ok(Async::Ready(())) => {}
                        Ok(Async::NotReady) => {}
                        Err(e) => error!("error completing message send: {:?}", e),
                    }
                }
                Entry::Vacant(_) => debug!("connection ID {:?} unknown", cid),
            }
        }
    }
}

struct Connection {
    addr: SocketAddr,
    state: ConnectionState<tls::ServerSession>,
    send: Sender<(SocketAddr, Vec<u8>)>,
    recv: Receiver<Vec<u8>>,
}

impl Connection {
    fn new(
        addr: SocketAddr,
        state: ConnectionState<tls::ServerSession>,
        send: Sender<(SocketAddr, Vec<u8>)>,
        recv: Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            addr,
            state,
            send,
            recv,
        }
    }
}

impl Future for Connection {
    type Item = ();
    type Error = ();
    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            let mut received = false;
            match self.recv.poll() {
                Ok(Async::Ready(Some(ref mut msg))) => {
                    self.state.handle(msg).unwrap();
                    received = true;
                }
                Ok(Async::Ready(None)) => {}
                Ok(Async::NotReady) => {}
                Err(e) => error!("error from server: {:?}", e),
            }

            let mut sent = false;
            match self.state.queued() {
                Ok(Some(msg)) => match self.send.start_send((self.addr.clone(), msg.clone())) {
                    Ok(AsyncSink::Ready) => {
                        sent = true;
                    }
                    Ok(AsyncSink::NotReady(_)) => {}
                    Err(e) => error!("error sending: {:?}", e),
                },
                Ok(None) => {}
                Err(e) => error!("error from connection state: {:?}", e),
            }

            let flushed = false;
            match self.send.poll_complete() {
                Ok(Async::Ready(())) => {}
                Ok(Async::NotReady) => {}
                Err(e) => error!("error from flushing sender: {:?}", e),
            }

            if !(received || sent || flushed) {
                break;
            }
        }
        Ok(Async::NotReady)
    }
}
