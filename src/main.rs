//! pg-starttls makes SNI routing work for clients that use PostgreSQL's
//! two-phase SSL negotiation (libpq's default, sslnegotiation=postgres).
//!
//! Such a client opens the connection in plaintext, sends an 8-byte SSLRequest
//! and then *waits* for the server's single-byte reply before it sends a TLS
//! ClientHello. The gateway therefore has no SNI to route on at the moment it
//! must pick a filter chain, and drops the connection.
//!
//! This shim is the party that answers. It replies "S", which unblocks the
//! client into sending a perfectly ordinary ClientHello -- SNI and all -- and
//! then splices that stream back into the gateway listener, where the existing
//! per-tenant TLSRoute chains route it exactly as they route a
//! sslnegotiation=direct connection. Routing stays defined solely by TLSRoutes;
//! this process never needs to know which tenants exist.

use std::env;
use std::fmt::Display;
use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Request codes sent in place of a protocol version in the startup packet.
const SSL_REQUEST_CODE: u32 = 80877103; // 0x04d2162f
const GSS_ENC_REQUEST_CODE: u32 = 80877104; // 0x04d21630

/// Opens every PROXY protocol v2 header. The gateway sends one so the shim can
/// learn who the real client is; the shim replays it upstream so the gateway can
/// attribute the re-entered connection to that client rather than to this pod.
/// Without it, every connection using the two-phase handshake would appear to
/// come from the pod network and would sail through any address-based policy.
const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Log lines go to stderr unstamped; the container runtime timestamps them.
macro_rules! fatal {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        std::process::exit(1);
    }};
}

struct Config {
    upstream_addr: String,
    handshake_timeout: Duration,
    dial_timeout: Duration,
    keepalive_period: Duration,
    /// How long established sessions get to finish after we stop accepting.
    /// Must leave room inside the pod's terminationGracePeriodSeconds, or the
    /// kubelet's SIGKILL lands before the drain completes and the whole exercise
    /// is wasted.
    drain_timeout: Duration,
}

#[tokio::main]
async fn main() {
    let listen_addr = env_or("LISTEN_ADDR", "0.0.0.0:5432");
    let upstream_addr = env::var("UPSTREAM_ADDR").unwrap_or_default();
    if upstream_addr.is_empty() {
        fatal!("UPSTREAM_ADDR is required (the gateway listener to hand the TLS stream back to)");
    }
    let cfg = Arc::new(Config {
        upstream_addr,
        handshake_timeout: duration_or("HANDSHAKE_TIMEOUT", Duration::from_secs(10)),
        dial_timeout: duration_or("DIAL_TIMEOUT", Duration::from_secs(10)),
        keepalive_period: Duration::from_secs(30),
        drain_timeout: duration_or("DRAIN_TIMEOUT", Duration::from_secs(20)),
    });

    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(listener) => listener,
        Err(err) => fatal!("listen on {listen_addr}: {err}"),
    };
    // Installed before the first accept. Until a handler exists the disposition
    // is still SIG_DFL, and the kernel discards default-disposition signals sent
    // to PID 1 of a namespace -- which is what this process is under
    // `ENTRYPOINT ["/pg-starttls"]`. A SIGTERM arriving in that window would be
    // dropped on the floor and the pod would sit there until SIGKILL.
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(sig) => sig,
        Err(err) => fatal!("installing SIGTERM handler: {err}"),
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(sig) => sig,
        Err(err) => fatal!("installing SIGINT handler: {err}"),
    };

    // Drain tracking without a counter: every connection task holds a clone of
    // the sender, so the receiver resolves exactly when the last one is dropped.
    // Nothing is ever sent over it.
    let (inflight, mut drained) = mpsc::channel::<()>(1);

    eprintln!(
        "pg-starttls listening on {listen_addr}, handing negotiated connections back to {}",
        cfg.upstream_addr
    );

    loop {
        let (conn, peer) = tokio::select! {
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    eprintln!("accept: {err}");
                    continue;
                }
            },
        };
        let cfg = Arc::clone(&cfg);
        let inflight = inflight.clone();
        tokio::spawn(async move {
            let _inflight = inflight;
            if let Err(err) = handle(conn, &cfg).await
                && !ordinary_close(&err)
            {
                eprintln!("{peer}: {err}");
            }
        });
    }

    // Dropping the listener is what makes this a drain rather than a pause: the
    // port stops accepting at once, so the set of sessions we are waiting on can
    // only shrink. Dropping our own sender leaves the tasks' clones as the only
    // ones outstanding.
    drop(listener);
    drop(inflight);

    eprintln!("shutting down: stopped accepting, draining established sessions");
    match timeout(cfg.drain_timeout, drained.recv()).await {
        Ok(_) => eprintln!("all sessions closed, exiting"),
        Err(_) => eprintln!(
            "drain budget of {:?} expired, closing remaining sessions",
            cfg.drain_timeout
        ),
    }
}

/// What the client's opening turned out to be.
enum Outcome {
    /// An SSLRequest was accepted. Hand the TLS stream that follows back to the
    /// gateway, replaying the PROXY header the gateway sent us if there was one.
    Splice(Option<Vec<u8>>),
    /// A ClientHello reached us, which means the gateway had SNI and still found
    /// no tenant chain for it. Splicing it back would return it here forever.
    RoutingLoop,
    /// A plaintext startup packet (sslmode=disable).
    PlaintextStartup,
}

/// Performs the SSL negotiation the gateway cannot, then gets out of the way.
async fn handle(mut down: TcpStream, cfg: &Config) -> io::Result<()> {
    // One budget for the whole negotiation, the way a socket read deadline
    // works: a client that dribbles bytes cannot hold the connection open
    // indefinitely. Rejecting a connection gets its own budget below, because a
    // client that spent the handshake budget still deserves to hear why.
    let outcome = match timeout(cfg.handshake_timeout, negotiate(&mut down)).await {
        Ok(outcome) => outcome?,
        Err(_) => return Err(io::Error::new(ErrorKind::TimedOut, "negotiation timed out")),
    };

    match outcome {
        Outcome::Splice(client_header) => splice(down, client_header, cfg).await,
        Outcome::RoutingLoop => {
            hang_up(&mut down).await;
            Err(io::Error::other(
                "direct TLS with unroutable SNI: refusing to avoid a routing loop",
            ))
        }
        Outcome::PlaintextStartup => {
            // Say why in the wire protocol, so the client prints a real error.
            let written = write_fatal(&mut down, "28000", "SSL connection is required").await;
            hang_up(&mut down).await;
            written.map_err(|err| ctx("writing error response", err))?;
            Err(io::Error::other(
                "plaintext startup packet rejected: SSL is required",
            ))
        }
    }
}

/// Answers the client's SSL negotiation and reports what it turned out to want.
async fn negotiate(down: &mut TcpStream) -> io::Result<Outcome> {
    let (client_header, mut pkt) = read_opening(down).await?;

    loop {
        let length = u32::from_be_bytes(pkt[0..4].try_into().unwrap());
        let code = u32::from_be_bytes(pkt[4..8].try_into().unwrap());

        // Every negotiation packet is exactly 8 bytes. Anything else is a client
        // that never intended to negotiate: either a bare ClientHello, or a
        // startup packet whose first field is its own big-endian length.
        if length != 8 {
            return Ok(if pkt[0] == 0x16 {
                Outcome::RoutingLoop
            } else {
                Outcome::PlaintextStartup
            });
        }

        match code {
            // Decline GSSAPI encryption; libpq then falls back to SSLRequest on
            // the same connection, so keep reading.
            GSS_ENC_REQUEST_CODE => {
                down.write_all(b"N")
                    .await
                    .map_err(|err| ctx("declining GSSENCRequest", err))?;
                down.read_exact(&mut pkt)
                    .await
                    .map_err(|err| ctx("reading negotiation packet", err))?;
            }
            SSL_REQUEST_CODE => {
                down.write_all(b"S")
                    .await
                    .map_err(|err| ctx("accepting SSLRequest", err))?;
                return Ok(Outcome::Splice(client_header));
            }
            // CancelRequest and anything else carry no SNI and no routable
            // information, so there is nowhere to send them.
            _ => {
                return Err(io::Error::other(format!(
                    "unroutable negotiation packet with code {code}"
                )));
            }
        }
    }
}

/// Consumes a PROXY protocol v2 header if one is present, returning it verbatim
/// for replay upstream along with the first negotiation packet behind it.
///
/// It commits to only four bytes before deciding which of the two it is reading:
/// a client using the two-phase handshake sends exactly 8 bytes and then waits,
/// so demanding a full 16-byte header up front would deadlock against a client
/// that was never going to send one. Four bytes is what both openings always
/// have, and they are unambiguous -- a header starts 0x0D0A0D0A, a negotiation
/// packet starts with its length.
async fn read_opening(down: &mut TcpStream) -> io::Result<(Option<Vec<u8>>, [u8; 8])> {
    let mut pkt = [0u8; 8];
    down.read_exact(&mut pkt[..4])
        .await
        .map_err(|err| ctx("reading connection opening", err))?;

    if pkt[..4] != PROXY_V2_SIGNATURE[..4] {
        down.read_exact(&mut pkt[4..])
            .await
            .map_err(|err| ctx("reading negotiation packet", err))?;
        return Ok((None, pkt));
    }

    let mut header = vec![0u8; 16];
    header[..4].copy_from_slice(&pkt[..4]);
    down.read_exact(&mut header[4..])
        .await
        .map_err(|err| ctx("reading proxy protocol header", err))?;
    if header[..12] != PROXY_V2_SIGNATURE {
        return Err(io::Error::other("malformed proxy protocol signature"));
    }

    let body_len = u16::from_be_bytes([header[14], header[15]]) as usize;
    header.resize(16 + body_len, 0);
    down.read_exact(&mut header[16..])
        .await
        .map_err(|err| ctx("reading proxy protocol address block", err))?;

    down.read_exact(&mut pkt)
        .await
        .map_err(|err| ctx("reading negotiation packet", err))?;
    Ok((Some(header), pkt))
}

/// Hands the now-TLS stream back to the gateway and copies both directions.
async fn splice(
    mut down: TcpStream,
    client_header: Option<Vec<u8>>,
    cfg: &Config,
) -> io::Result<()> {
    let dial = TcpStream::connect(&cfg.upstream_addr);
    let mut up = match timeout(cfg.dial_timeout, dial).await {
        Ok(dialed) => dialed.map_err(|err| ctx(format!("dialing {}", cfg.upstream_addr), err))?,
        Err(_) => {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("dialing {}: timed out", cfg.upstream_addr),
            ));
        }
    };

    // Re-announce the original client before any payload, so the gateway
    // attributes this connection to them rather than to this pod.
    if let Some(header) = client_header {
        up.write_all(&header)
            .await
            .map_err(|err| ctx("replaying proxy protocol header", err))?;
    }

    // Idle Postgres sessions are legitimately long-lived, so lean on keepalives
    // rather than a timeout to reap connections whose peer disappeared.
    let keepalive = TcpKeepalive::new()
        .with_time(cfg.keepalive_period)
        .with_interval(cfg.keepalive_period);
    for conn in [&down, &up] {
        let _ = SockRef::from(conn).set_tcp_keepalive(&keepalive);
    }

    // Copying is bidirectional but each direction ends on its own: an EOF on one
    // is passed along as a FIN on the other and the remaining direction keeps
    // going, so a client that half-closes still receives the server's last bytes.
    copy_bidirectional(&mut down, &mut up).await?;
    Ok(())
}

/// Emits a Postgres ErrorResponse so clients report the real reason.
async fn write_fatal(down: &mut TcpStream, sqlstate: &str, message: &str) -> io::Result<()> {
    let mut body = Vec::new();
    for (code, val) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        body.push(code);
        body.extend_from_slice(val.as_bytes());
        body.push(0);
    }
    body.push(0); // terminator for the field list

    let mut msg = vec![b'E'];
    msg.extend_from_slice(&((4 + body.len()) as u32).to_be_bytes());
    msg.extend_from_slice(&body);
    down.write_all(&msg).await
}

/// Ends a rejected connection without losing what was just written. Only the
/// 8-byte header of the client's message was consumed, so the rest is still
/// queued; closing a socket with unread bytes makes the kernel send RST, which
/// would discard the error response instead of delivering it. Sending FIN first
/// and then draining leaves nothing for the close to reset.
async fn hang_up(down: &mut TcpStream) {
    let _ = down.shutdown().await;
    let mut discard = tokio::io::sink();
    let _ = timeout(Duration::from_secs(2), tokio::io::copy(down, &mut discard)).await;
}

/// Describes what failed while preserving the underlying error's kind, so a
/// plain disconnect stays recognisable to [`ordinary_close`] underneath its
/// description.
fn ctx(what: impl Display, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{what}: {err}"))
}

/// Reports whether err is just a connection ending, rather than something worth
/// a log line. Readiness probes connect and hang up without sending anything,
/// and clients routinely vanish mid-session, so without this the log is nothing
/// but noise.
fn ordinary_close(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::NotConnected
    )
}

fn env_or(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => fallback.to_string(),
    }
}

fn duration_or(key: &str, fallback: Duration) -> Duration {
    match env::var(key) {
        Ok(v) if !v.is_empty() => match humantime::parse_duration(&v) {
            Ok(d) => d,
            Err(err) => fatal!("{key}: {err}"),
        },
        _ => fallback,
    }
}
