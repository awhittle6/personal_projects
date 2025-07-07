use anyhow::Result;
use futures::future;
use h3::error::ConnectionError;
use tokio::io::AsyncWriteExt;
use std::{net::SocketAddr, sync::Arc};

#[derive(Debug)]
struct SkipCertVerification;

impl rustls::client::danger::ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider().install_default().unwrap();

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from({
            let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        crypto
        }).unwrap()
    )));
    let connection = endpoint.connect("127.0.0.1:4433".parse::<SocketAddr>()?, "localhost")?.await?;
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let drive = async move {
        Err::<(), ConnectionError>(future::poll_fn(|cx| driver.poll_close(cx)).await)
};          

    let request = async move {
        for path in ["/"] {
            let req = http::Request::get(path).header("host", "localhost").body(())?;
            let mut stream = send_request.send_request(req).await?;
            stream.finish().await?;
            let response = stream.recv_response().await?;
            println!("{}: {}", path, response.status());
            while let Some(mut chunk) = stream.recv_data().await? {
                tokio::io::stdout().write_all_buf(&mut chunk).await.unwrap();
            }
            println!();
        } 
        Ok::<_, anyhow::Error>(())
    };
    let _ = tokio::join!(request, drive);
    endpoint.wait_idle().await;
    Ok(())
}