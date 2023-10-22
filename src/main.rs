use bytes::BytesMut;
use hyper::{
    client::HttpConnector,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Request, Response, Server, Uri,
};
use rustls::{Certificate, OwnedTrustAnchor, PrivateKey, ServerConfig, ServerName};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::main]
async fn main() {
    let addr = ([127, 0, 0, 1], 3000).into();
    let client = Client::new();

    let service = make_service_fn(move |_| {
        let client = client.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| proxy(req, client.clone()))) }
    });

    let server = Server::bind(&addr).serve(service);

    println!("HTTP Proxy is running on http://{}", addr);

    server.await.unwrap();
}

async fn proxy(
    req: Request<Body>,
    client: Client<HttpConnector>,
) -> Result<Response<Body>, hyper::Error> {
    if req.method() == hyper::Method::CONNECT {
        tokio::task::spawn(async move {
            let uri = req.uri().clone();
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, uri).await {
                        eprintln!("server io error: {}", e);
                    };
                }
                Err(e) => eprintln!("upgrade error: {}", e),
            }
        });

        Ok(Response::new(Body::empty()))
    } else {
        client.request(req).await
    }
}

async fn tunnel(upgraded: Upgraded, uri: Uri) -> std::io::Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec![uri.host().unwrap().to_string()]).unwrap();
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(cert.serialize_der().unwrap())],
            PrivateKey(cert.serialize_private_key_der()),
        )
        .unwrap();

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let mut stream_from_client = tls_acceptor.accept(upgraded).await?;

    // Connect to remote server

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth(); // i guess this was previously the default?
    let connector = TlsConnector::from(Arc::new(config));
    let server = TcpStream::connect(uri.authority().unwrap().to_string()).await?;
    let mut stream_to_server = connector
        .connect(ServerName::try_from(uri.host().unwrap()).unwrap(), server)
        .await?;

    let mut buf_server = BytesMut::new();
    let mut buf_client = BytesMut::new();
    loop {
        tokio::select! {
            res = stream_to_server.read_buf(&mut buf_server) => {
                if let Ok(n) = res {
                    if n == 0 {
                        break;
                    }
                    let _ = stream_from_client.write_all(&buf_server[buf_server.len() - n..]).await;
                }else {
                    break;
                }
            }
            res = stream_from_client.read_buf(&mut buf_client) => {
                if let Ok(n) = res {
                    if n == 0 {
                        break;
                    }
                    let _ = stream_to_server.write_all(&buf_client[buf_client.len() - n..]).await;
                }else {
                    break;
                }
            }
        }
    }

    println!("Client sent: {:?}", buf_client);
    println!("Client received: {:?}", buf_server);

    Ok(())
}
