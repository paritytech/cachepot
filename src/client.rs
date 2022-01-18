// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::errors::*;
use crate::protocol::{Request, Response};
use crate::util;
use byteorder::{BigEndian, ByteOrder};
use retry::{delay::Fixed, retry};
use std::io::{self, BufReader, BufWriter, Read};
use std::net::TcpStream;

/// A connection to an cachepot server.
pub struct CoordinatorConnection {
    /// A reader for the socket connected to the coordinator.
    reader: BufReader<TcpStream>,
    /// A writer for the socket connected to the coordinator.
    writer: BufWriter<TcpStream>,
}

impl CoordinatorConnection {
    /// Create a new connection using `stream`.
    pub fn new(stream: TcpStream) -> io::Result<CoordinatorConnection> {
        let writer = stream.try_clone()?;
        Ok(CoordinatorConnection {
            reader: BufReader::new(stream),
            writer: BufWriter::new(writer),
        })
    }

    /// Send `request` to the coordinator, read and return a `Response`.
    pub fn request(&mut self, request: Request) -> Result<Response> {
        trace!("CoordinatorConnection::request");
        util::write_length_prefixed_bincode(&mut self.writer, request)?;
        trace!("CoordinatorConnection::request: sent request");
        self.read_one_response()
    }

    /// Read a single `Response` from the coordinator.
    pub fn read_one_response(&mut self) -> Result<Response> {
        trace!("CoordinatorConnection::read_one_response");
        let mut bytes = [0; 4];
        self.reader
            .read_exact(&mut bytes)
            .context("Failed to read response header")?;
        let len = BigEndian::read_u32(&bytes);
        trace!("Should read {} more bytes", len);
        let mut data = vec![0; len as usize];
        self.reader.read_exact(&mut data)?;
        trace!("Done reading");
        Ok(bincode::deserialize(&data)?)
    }
}

/// Establish a TCP connection to an cachepot coordinator listening on `port`.
pub fn connect_to_coordinator(port: u16) -> io::Result<CoordinatorConnection> {
    trace!("connect_to_coordinator({})", port);
    let stream = TcpStream::connect(("127.0.0.1", port))?;
    CoordinatorConnection::new(stream)
}

/// Attempt to establish a TCP connection to an cachepot coordinator listening on `port`.
///
/// If the connection fails, retry a few times.
pub fn connect_with_retry(port: u16) -> io::Result<CoordinatorConnection> {
    trace!("connect_with_retry({})", port);
    // TODOs:
    // * Pass the coordinator Child in here, so we can stop retrying
    //   if the process exited.
    // * Send a pipe handle to the coordinator process so it can notify
    //   us once it starts the coordinator instead of us polling.
    match retry(Fixed::from_millis(500).take(10), || {
        connect_to_coordinator(port)
    }) {
        Ok(conn) => Ok(conn),
        _ => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Connection to coordinator timed out",
        )),
    }
}
