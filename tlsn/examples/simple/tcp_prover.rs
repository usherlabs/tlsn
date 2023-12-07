/// Runs a simple Prover which connects to the Notary and notarizes a request/response from
/// example.com. The Prover then generates a proof and writes it to disk.
///
/// The example uses the notary server implemented in ./simple_notary.rs
use futures::AsyncWriteExt;
use std::ops::Range;
use tlsn_core::proof::TlsProof;
use tokio::io::AsyncWriteExt as _;

use hyper::{
    body::to_bytes,
    client::conn::Parts,
    Body, Request, StatusCode,
};
use rustls::{Certificate, ClientConfig, RootCertStore};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use notary_server::{
    read_pem_file, NotarizationProperties,
    NotarizationSessionRequest, NotarizationSessionResponse,
    ServerProperties
};

// Setting of the application server
const SERVER_DOMAIN: &str = "baconipsum.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";
const REQUEST_URI: &str = "/api/?type=meat-and-filler"; // "/";

// Setting of the notary server — make sure these are the same with those in ./simple_notary.rs
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047; // 8080;

const NOTARY_CA_CERT_PATH: &str = "../../notary-server/fixture/tls/rootCA.crt";
// const NOTARY_CA_CERT_BYTES: &[u8] = include_bytes!("../../../notary-server/fixture/tls/rootCA.crt");

pub struct NotaryServerPropertiesSlim {
    /// Name and address of the notary server
    pub server: ServerProperties,
    /// Setting for notarization
    pub notarization: NotarizationProperties,
    // /// File path of private key and certificate (in PEM format) used for establishing TLS with prover
    // pub tls_signature: TLSSignatureProperties,
    // /// File path of private key (in PEM format) used to sign the notarization
    // pub notary_signature: NotarySignatureProperties,
    // /// Setting for logging/tracing
    // pub tracing: TracingProperties,
    // /// Setting for authorization
    // pub authorization: AuthorizationProperties,
}

#[tokio::main]
async fn main() {
    // Notary server configuration setup
    let notary_config: NotaryServerPropertiesSlim = NotaryServerPropertiesSlim {
        server: ServerProperties {
            name: "tlsnotaryserver.io".to_string(),
            host: NOTARY_HOST.to_string(),
            port: NOTARY_PORT,
        },
        notarization: NotarizationProperties {
            max_transcript_size: 1 << 14,
        }
    };

    // Initialize logging
    tracing_subscriber::fmt::init();

    // Connect to the Notary via TLS-TCP
    let mut certificate_file_reader = read_pem_file(NOTARY_CA_CERT_PATH).await.unwrap();
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut certificate_file_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_store = RootCertStore::empty();
    root_store.add(&certificate).unwrap();

    let client_notary_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

    let notary_host = notary_config.server.host.clone();
    let notary_port = notary_config.server.port;
    let notary_socket = tokio::net::TcpStream::connect(SocketAddr::new(
        IpAddr::V4(notary_host.parse().unwrap()),
        notary_port,
    ))
    .await
    .unwrap();

    let notary_tls_socket = notary_connector
        .connect(
            notary_config.server.name.as_str().try_into().unwrap(),
            notary_socket,
        )
        .await
        .unwrap();

    // Attach the hyper HTTP client to the notary TLS connection to send request to the /session endpoint to configure notarization and obtain session id
    let (mut request_sender, connection) = hyper::client::conn::handshake(notary_tls_socket)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to configure notarization
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: notary_server::ClientType::Tcp,
        max_transcript_size: Some(notary_config.notarization.max_transcript_size),
    })
    .unwrap();
    let request = Request::builder()
        .uri(format!("https://{notary_host}:{notary_port}/session"))
        .method("POST")
        .header("Host", notary_host.clone())
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    println!("Sending configuration request");

    let response = request_sender.send_request(request).await.unwrap();

    println!("Sent configuration request");

    assert!(response.status() == StatusCode::OK);

    println!("Response OK");

    // Pretty printing :)
    let payload = to_bytes(response.into_body()).await.unwrap().to_vec();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    println!("Notarization response: {:?}", notarization_response,);

    // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
    let request = Request::builder()
        // Need to specify the session_id so that notary server knows the right configuration to use
        // as the configuration is set in the previous HTTP call
        .uri(format!(
            "https://{}:{}/notarize?sessionId={}",
            notary_host,
            notary_port,
            notarization_response.session_id.clone()
        ))
        .method("GET")
        .header("Host", notary_host)
        .header("Connection", "Upgrade")
        // Need to specify this upgrade header for server to extract tcp connection later
        .header("Upgrade", "TCP")
        .body(Body::empty())
        .unwrap();

    println!("Sending notarization request");

    let response = request_sender.send_request(request).await.unwrap();

    println!("Sent notarization request");

    assert!(response.status() == StatusCode::SWITCHING_PROTOCOLS);

    println!("Switched protocol OK");

    // Claim back the TCP socket after HTTP exchange is done so that client can use it for notarization
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // let mut root_store = tls_core::anchors::RootCertStore::empty();
    // root_store
    //     .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
    //     .unwrap();

    // Basic default prover config — use the responded session id from notary server
    let prover_config = ProverConfig::builder()
        .id(notarization_response.session_id)
        .server_dns(SERVER_DOMAIN)
        // .root_cert_store(root_store)
        .build()
        .unwrap();

    // Bind the Prover to the sockets
    let prover = Prover::new(prover_config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_connection.compat())
        .await
        .unwrap();

    let connection_task = tokio::spawn(connection.without_shutdown());

    let request = Request::builder()
        .uri(format!("https://{}/{}", SERVER_DOMAIN, REQUEST_URI))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    println!("Sending request to server: {:?}", request);

    let response = request_sender.send_request(request).await.unwrap();

    println!(
        "Received response status from server: {:?}",
        response.status()
    );

    assert!(response.status() == StatusCode::OK);

    println!(
        "Received response from server: {:?}",
        String::from_utf8_lossy(&to_bytes(response.into_body()).await.unwrap())
    );

    // let mut server_tls_conn = server_task.await.unwrap().unwrap();

    // // Make sure the server closes cleanly (sends close notify)
    // server_tls_conn.close().await.unwrap();

    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();

    client_socket.close().await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();

    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    builder.commit_sent(0..sent_len).unwrap();
    builder.commit_recv(0..recv_len).unwrap();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let proof_builder = notarized_session.data().build_substrings_proof();

    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
    };

    println!("Done notarization!");


    // // Identify the ranges in the outbound data which contain data which we want to disclose
    // let (sent_public_ranges, _) = find_ranges(
    //     prover.sent_transcript().data(),
    //     &[
    //         // Redact the value of the "User-Agent" header. It will NOT be disclosed.
    //         USER_AGENT.as_bytes(),
    //     ],
    // );

    // // Identify the ranges in the inbound data which contain data which we want to disclose
    // let (recv_public_ranges, _) = find_ranges(
    //     prover.recv_transcript().data(),
    //     &[
    //         // Redact the value of the title. It will NOT be disclosed.
    //         "Example Domain".as_bytes(),
    //     ],
    // );

    // let builder = prover.commitment_builder();

    // // Commit to each range of the public outbound data which we want to disclose
    // let sent_commitments: Vec<_> = sent_public_ranges
    //     .iter()
    //     .map(|r| builder.commit_sent(r.clone()).unwrap())
    //     .collect();
    // // Commit to each range of the public inbound data which we want to disclose
    // let recv_commitments: Vec<_> = recv_public_ranges
    //     .iter()
    //     .map(|r| builder.commit_recv(r.clone()).unwrap())
    //     .collect();

    // // Finalize, returning the notarized session
    // let notarized_session = prover.finalize().await.unwrap();

    // // Create a proof for all committed data in this session
    // let mut proof_builder = notarized_session.data().build_substrings_proof();

    // // Reveal all the public ranges
    // for commitment_id in sent_commitments {
    //     proof_builder.reveal(commitment_id).unwrap();
    // }
    // for commitment_id in recv_commitments {
    //     proof_builder.reveal(commitment_id).unwrap();
    // }

    // let substrings_proof = proof_builder.build().unwrap();

    // let proof = TlsProof {
    //     session: notarized_session.session_proof(),
    //     substrings: substrings_proof,
    // };

    // Write the proof to a file
    let mut file = tokio::fs::File::create("proof.json").await.unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    println!("Notarization completed successfully!");
    println!("The proof has been written to proof.json");
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}
