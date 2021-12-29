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
#[cfg(feature = "dist-client")]
pub use self::client::Client;
#[cfg(feature = "dist-server")]
pub use self::server::Server;
#[cfg(feature = "dist-server")]
pub use self::server::{
    ClientAuthCheck, ClientVisibleMsg, Scheduler, ServerAuthCheck, HEARTBEAT_TIMEOUT,
};

mod common {
    #[cfg(any(feature = "dist-client", feature = "dist-server"))]
    use hyperx::header;
    #[cfg(feature = "dist-server")]
    use std::collections::HashMap;
    use std::fmt;

    use crate::dist;

    use crate::errors::*;
    use crate::util::RequestExt;

    // Note that content-length is necessary due to https://github.com/tiny-http/tiny-http/issues/147
    pub trait ReqwestRequestBuilderExt: Sized {
        fn bincode<T: serde::Serialize + ?Sized>(self, bincode: &T) -> Result<Self>;
        fn bytes(self, bytes: Vec<u8>) -> Self;
        fn bearer_auth(self, token: String) -> Self;
    }

    impl ReqwestRequestBuilderExt for reqwest::RequestBuilder {
        fn bincode<T: serde::Serialize + ?Sized>(self, bincode: &T) -> Result<Self> {
            let bytes =
                bincode::serialize(bincode).context("Failed to serialize body to bincode")?;
            Ok(self.bytes(bytes))
        }
        fn bytes(self, bytes: Vec<u8>) -> Self {
            self.set_header(header::ContentType::octet_stream())
                .set_header(header::ContentLength(bytes.len() as u64))
                .body(bytes)
        }
        fn bearer_auth(self, token: String) -> Self {
            self.set_header(header::Authorization(header::Bearer { token }))
        }
    }

    pub async fn bincode_req<T: serde::de::DeserializeOwned + 'static>(
        req: reqwest::RequestBuilder,
    ) -> Result<T> {
        // Work around tiny_http issue #151 by disabling HTTP pipeline with
        // `Connection: close`.
        let res = req.set_header(header::Connection::close()).send().await?;

        let status = res.status();
        let bytes = res.bytes().await?;
        if !status.is_success() {
            let errmsg = format!(
                "Error {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes)
            );
            if status.is_client_error() {
                anyhow::bail!(HttpClientError(errmsg));
            } else {
                anyhow::bail!(errmsg);
            }
        } else {
            Ok(bincode::deserialize(&*bytes)?)
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct JobJwt {
        pub job_id: dist::JobId,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum AllocJobHttpResponse {
        Success {
            job_alloc: dist::JobAlloc,
            need_toolchain: bool,
            cert_digest: Vec<u8>,
        },
        Fail {
            msg: String,
        },
    }
    impl AllocJobHttpResponse {
        #[cfg(feature = "dist-server")]
        pub fn from_alloc_job_result(
            res: dist::AllocJobResult,
            certs: &HashMap<dist::ServerId, (Vec<u8>, Vec<u8>)>,
        ) -> Self {
            match res {
                dist::AllocJobResult::Success {
                    job_alloc,
                    need_toolchain,
                } => {
                    if let Some((digest, _)) = certs.get(&job_alloc.server_id) {
                        AllocJobHttpResponse::Success {
                            job_alloc,
                            need_toolchain,
                            cert_digest: digest.to_owned(),
                        }
                    } else {
                        AllocJobHttpResponse::Fail {
                            msg: format!(
                                "missing certificates for server {}",
                                job_alloc.server_id.addr()
                            ),
                        }
                    }
                }
                dist::AllocJobResult::Fail { msg } => AllocJobHttpResponse::Fail { msg },
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ServerCertificateHttpResponse {
        pub cert_digest: Vec<u8>,
        pub cert_pem: Vec<u8>,
    }

    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HeartbeatServerHttpRequest {
        pub jwt_key: Vec<u8>,
        pub num_cpus: usize,
        pub server_nonce: dist::ServerNonce,
        pub cert_digest: Vec<u8>,
        pub cert_pem: Vec<u8>,
    }
    // cert_pem is quite long so elide it (you can retrieve it by hitting the server url anyway)
    impl fmt::Debug for HeartbeatServerHttpRequest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let HeartbeatServerHttpRequest {
                jwt_key,
                num_cpus,
                server_nonce,
                cert_digest,
                cert_pem,
            } = self;
            write!(f, "HeartbeatServerHttpRequest {{ jwt_key: {:?}, num_cpus: {:?}, server_nonce: {:?}, cert_digest: {:?}, cert_pem: [...{} bytes...] }}", jwt_key, num_cpus, server_nonce, cert_digest, cert_pem.len())
        }
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RunJobHttpRequest {
        pub command: dist::CompileCommand,
        pub outputs: Vec<String>,
    }
}

pub mod urls {
    use crate::dist::{JobId, ServerId};

    pub fn scheduler_alloc_job(scheduler_url: &reqwest::Url) -> reqwest::Url {
        scheduler_url
            .join("/api/v1/scheduler/alloc_job")
            .expect("failed to create alloc job url")
    }
    pub fn scheduler_server_certificate(
        scheduler_url: &reqwest::Url,
        server_id: ServerId,
    ) -> reqwest::Url {
        scheduler_url
            .join(&format!(
                "/api/v1/scheduler/server_certificate/{}",
                server_id.addr()
            ))
            .expect("failed to create server certificate url")
    }
    pub fn scheduler_heartbeat_server(scheduler_url: &reqwest::Url) -> reqwest::Url {
        scheduler_url
            .join("/api/v1/scheduler/heartbeat_server")
            .expect("failed to create heartbeat url")
    }
    pub fn scheduler_job_state(scheduler_url: &reqwest::Url, job_id: JobId) -> reqwest::Url {
        scheduler_url
            .join(&format!("/api/v1/scheduler/job_state/{}", job_id))
            .expect("failed to create job state url")
    }
    pub fn scheduler_status(scheduler_url: &reqwest::Url) -> reqwest::Url {
        scheduler_url
            .join("/api/v1/scheduler/status")
            .expect("failed to create alloc job url")
    }

    pub fn server_assign_job(server_id: ServerId, job_id: JobId) -> reqwest::Url {
        let url = format!(
            "https://{}/api/v1/distserver/assign_job/{}",
            server_id.addr(),
            job_id
        );
        reqwest::Url::parse(&url).expect("failed to create assign job url")
    }
    pub fn server_submit_toolchain(server_id: ServerId, job_id: JobId) -> reqwest::Url {
        let url = format!(
            "https://{}/api/v1/distserver/submit_toolchain/{}",
            server_id.addr(),
            job_id
        );
        reqwest::Url::parse(&url).expect("failed to create submit toolchain url")
    }
    pub fn server_run_job(server_id: ServerId, job_id: JobId) -> reqwest::Url {
        let url = format!(
            "https://{}/api/v1/distserver/run_job/{}",
            server_id.addr(),
            job_id
        );
        reqwest::Url::parse(&url).expect("failed to create run job url")
    }
}

#[cfg(feature = "dist-server")]
mod server {
    use crate::jwt;
    use rand::{rngs::OsRng, RngCore};
    use std::collections::HashMap;
    use std::result::Result as StdResult;
    use std::sync::Arc;
    use std::time::Duration;
    use void::Void;

    use super::common::{
        bincode_req, AllocJobHttpResponse, HeartbeatServerHttpRequest, JobJwt,
        ReqwestRequestBuilderExt, RunJobHttpRequest, ServerCertificateHttpResponse,
    };
    use super::urls;
    use crate::dist::{
        self, AssignJobResult, HeartbeatServerResult, JobId, JobState, ServerId, ServerNonce,
        Toolchain, UpdateJobStateResult,
    };
    use crate::errors::*;

    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
    const HEARTBEAT_ERROR_INTERVAL: Duration = Duration::from_secs(10);
    pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

    use chrono::Datelike;
    use chrono::Timelike;
    use picky::key::{PrivateKey, PublicKey};
    use picky::x509::certificate::CertificateBuilder;
    use picky::x509::date::UTCDate;
    use picky::x509::extension::ExtendedKeyUsage;
    use picky::x509::name::{DirectoryName, GeneralNames};

    use picky::{hash::HashAlgorithm, signature::SignatureAlgorithm};
    use sha2::Digest;
    use std::net::{IpAddr, SocketAddr};
    use tokio::sync::Mutex;

    pub(crate) fn create_https_cert_and_privkey(
        addr: SocketAddr,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut rng = OsRng;
        let bits = 2048;
        let rsa_key = rsa::RSAPrivateKey::new(&mut rng, bits)?;

        let sk_pkcs8 = rsa::PrivateKeyPemEncoding::to_pem_pkcs8(&rsa_key)?;
        let pk_pkcs8 = rsa::PublicKeyPemEncoding::to_pem_pkcs8(&*rsa_key)?;

        // convert to picky
        let sk = PrivateKey::from_pem_str(sk_pkcs8.as_str())?;
        let pk = PublicKey::from_pem_str(pk_pkcs8.as_str())?;

        let today = chrono::Utc::now().naive_utc();
        let expires = today + chrono::Duration::days(365);
        let start = UTCDate::new(
            today.year() as u16,
            today.month() as u8,
            today.day() as u8,
            today.time().hour() as u8,
            today.time().minute() as u8,
            today.time().second() as u8,
        )
        .unwrap();
        let end = UTCDate::new(
            expires.year() as u16,
            expires.month() as u8,
            expires.day() as u8,
            expires.time().hour() as u8,
            expires.time().minute() as u8,
            expires.time().second() as u8,
        )
        .unwrap();

        let extended_key_usage = ExtendedKeyUsage::new(vec![picky::oids::kp_server_auth()]);

        let name = addr.to_string();

        let issuer_name = DirectoryName::new_common_name(name.clone());
        let subject_name = DirectoryName::new_common_name(name);
        let octets = match addr.ip() {
            IpAddr::V4(inner) => inner.octets().to_vec(),
            IpAddr::V6(inner) => inner.octets().to_vec(),
        };
        let subject_alt_name = GeneralNames::new(picky::x509::name::GeneralName::IpAddress(octets));

        let cert = CertificateBuilder::new()
            .ca(false)
            .validity(start, end)
            .subject(subject_name, pk)
            .subject_alt_name(subject_alt_name)
            .serial_number(vec![1]) // cannot be 0 according to picky internal notes
            .signature_hash_type(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1))
            .extended_key_usage(extended_key_usage)
            .self_signed(issuer_name, &sk)
            .build()?;

        let cert_digest = {
            let der = cert.to_der()?;
            let mut state = sha2::Sha256::new();
            state.update(&der);
            state.finalize()
        }
        .as_slice()
        .to_vec();

        let cert_pem = cert.to_pem()?;
        let cert_pem = cert_pem.to_string().as_bytes().to_vec();
        let privkey_pem = sk_pkcs8.as_bytes().to_vec();
        Ok((cert_digest, cert_pem, privkey_pem))
    }

    // Messages that are non-sensitive and can be sent to the client
    #[derive(Debug)]
    pub struct ClientVisibleMsg(String);
    impl ClientVisibleMsg {
        pub fn from_nonsensitive(s: String) -> Self {
            ClientVisibleMsg(s)
        }
    }

    #[async_trait]
    pub trait ClientAuthCheck: Send + Sync {
        async fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg>;
    }
    pub type ServerAuthCheck = Arc<dyn Fn(&str) -> Option<ServerId> + Send + Sync>;

    const JWT_KEY_LENGTH: usize = 256 / 8;
    lazy_static! {
        static ref JWT_HEADER: jwt::Header = jwt::Header::new(jwt::Algorithm::HS256);
        static ref JWT_VALIDATION: jwt::Validation = jwt::Validation {
            leeway: 0,
            validate_exp: false,
            validate_nbf: false,
            aud: None,
            iss: None,
            sub: None,
            algorithms: vec![jwt::Algorithm::HS256],
        };
    }

    // Based on try_or_400 in rouille, but with logging
    #[derive(Serialize)]
    pub struct ErrJson {
        description: String,
        cause: Option<Box<ErrJson>>,
    }

    impl ErrJson {
        fn from_err<E: ?Sized + std::error::Error>(err: &E) -> ErrJson {
            let cause = err.source().map(ErrJson::from_err).map(Box::new);
            ErrJson {
                description: err.to_string(),
                cause,
            }
        }

        fn into_data(self) -> String {
            serde_json::to_string(&self).expect("infallible serialization for ErrJson failed")
        }
    }

    // Generation and verification of job auth
    struct JWTJobAuthorizer {
        server_key: Vec<u8>,
    }
    impl JWTJobAuthorizer {
        fn new(server_key: Vec<u8>) -> Self {
            Self { server_key }
        }
    }
    impl dist::JobAuthorizer for JWTJobAuthorizer {
        fn generate_token(&self, job_id: JobId) -> Result<String> {
            let claims = JobJwt { job_id };
            let key = jwt::EncodingKey::from_secret(&self.server_key);
            jwt::encode(&JWT_HEADER, &claims, &key)
                .map_err(|e| anyhow!("Failed to create JWT for job: {}", e))
        }
        fn verify_token(&self, job_id: JobId, token: &str) -> Result<()> {
            let valid_claims = JobJwt { job_id };
            let key = jwt::DecodingKey::from_secret(&self.server_key);
            jwt::decode(token, &key, &JWT_VALIDATION)
                .map_err(|e| anyhow!("JWT decode failed: {}", e))
                .and_then(|res| {
                    fn identical_t<T>(_: &T, _: &T) {}
                    identical_t(&res.claims, &valid_claims);
                    if res.claims == valid_claims {
                        Ok(())
                    } else {
                        Err(anyhow!("mismatched claims"))
                    }
                })
        }
    }

    #[test]
    fn test_job_token_verification() {
        use crate::dist::JobAuthorizer;
        let ja = JWTJobAuthorizer::new(vec![1, 2, 2]);

        let job_id = JobId(55);
        let token = ja.generate_token(job_id).unwrap();

        let job_id2 = JobId(56);
        let token2 = ja.generate_token(job_id2).unwrap();

        let ja2 = JWTJobAuthorizer::new(vec![1, 2, 3]);

        // Check tokens are deterministic
        assert_eq!(token, ja.generate_token(job_id).unwrap());
        // Check token verification works
        assert!(ja.verify_token(job_id, &token).is_ok());
        assert!(ja.verify_token(job_id, &token2).is_err());
        assert!(ja.verify_token(job_id2, &token).is_err());
        assert!(ja.verify_token(job_id2, &token2).is_ok());
        // Check token verification with a different key fails
        assert!(ja2.verify_token(job_id, &token).is_err());
        assert!(ja2.verify_token(job_id2, &token2).is_err());
    }

    mod distserver_api_v1 {
        use thiserror::Error;

        pub use filters::api;

        #[derive(Error, Debug)]
        pub enum Error {
            #[error("failed to assign job")]
            AssignJob,
            #[error("no Authorization header")]
            NoAuthorizationHeader,
            #[error("authorization header is wrong")]
            AuthorizationHeaderBroken,
            #[error("bearer_auth_failed")]
            BearerAuthFailed,
            #[error("")]
            Bincode,
        }

        impl warp::reject::Reject for Error {}

        pub(super) mod filters {
            use std::convert::Infallible;
            use std::sync::{atomic, Arc};
            use warp::{
                http::{
                    header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE},
                    HeaderMap, HeaderValue, StatusCode,
                },
                reply::{self, Response},
                Filter, Rejection, Reply,
            };

            use super::{handlers, Error};
            use crate::dist::{
                self,
                http::server::{ClientVisibleMsg, ErrJson},
                JobAuthorizer, JobId, ServerIncoming,
            };

            fn bearer_http_auth(headers: &HeaderMap<HeaderValue>) -> Result<String, Error> {
                let header = headers
                    .get(AUTHORIZATION)
                    .ok_or(Error::NoAuthorizationHeader)?;

                let header = header
                    .to_str()
                    .map_err(|_| Error::AuthorizationHeaderBroken)?;

                let mut split = header.splitn(2, |c| c == ' ');

                let authtype = split.next().ok_or(Error::AuthorizationHeaderBroken)?;

                if authtype != "Bearer" {
                    return Err(Error::AuthorizationHeaderBroken);
                }

                Ok(split
                    .next()
                    .ok_or(Error::AuthorizationHeaderBroken)?
                    .to_string())
            }

            async fn authorize(
                job_id: JobId,
                authorizer: Arc<dyn JobAuthorizer>,
                headers: HeaderMap<HeaderValue>, // TODO: Only need an Authorization header
            ) -> Result<JobId, Rejection> {
                let token = bearer_http_auth(&headers)?;

                authorizer
                    .verify_token(job_id, &token)
                    .map_err(|_| Error::BearerAuthFailed)?;

                Ok(job_id)
            }

            fn with_job_authorizer(
                job_authorizer: Arc<dyn JobAuthorizer>,
            ) -> impl Filter<Extract = (Arc<dyn JobAuthorizer>,), Error = Infallible> + Clone
            {
                warp::any().map(move || job_authorizer.clone())
            }

            fn with_requester(
                requester: Arc<dyn dist::ServerOutgoing>,
            ) -> impl Filter<Extract = (Arc<dyn dist::ServerOutgoing>,), Error = Infallible> + Clone
            {
                warp::any().map(move || requester.clone())
            }

            fn with_server_incoming_handler(
                handler: Arc<dyn ServerIncoming>,
            ) -> impl Filter<Extract = (Arc<dyn ServerIncoming>,), Error = Infallible> + Clone
            {
                warp::any().map(move || handler.clone())
            }

            async fn prepare_response<T>(
                content: T,
                accept: Option<String>,
            ) -> Result<warp::reply::Response, Rejection>
            where
                T: serde::Serialize,
            {
                match accept {
                    Some(accept) if accept == "application/json" => {
                        Ok(warp::reply::json(&content).into_response())
                    }
                    _ => Ok(warp::http::Response::builder()
                        .body(hyper::Body::from(
                            bincode::serialize(&content).map_err(|_| Error::Bincode)?,
                        ))
                        .map_err(|_| Error::Bincode)?),
                }
            }

            // POST /api/v1/distserver/assign_job/{job_id: JobId}
            fn assign_job(
                request_counter: Arc<atomic::AtomicUsize>,
                job_authorizer: Arc<dyn dist::JobAuthorizer>,
                handler: Arc<dyn dist::ServerIncoming>,
            ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
                let with_request_id =
                    warp::any().map(move || request_counter.fetch_add(1, atomic::Ordering::SeqCst));

                warp::path!("api" / "v1" / "distserver" / "assign_job" / JobId)
                    .and(warp::post())
                    .and(with_job_authorizer(job_authorizer))
                    .and(warp::header::headers_cloned())
                    .and_then(authorize)
                    .and(toolchain())
                    .and(with_server_incoming_handler(handler))
                    .and(with_request_id)
                    .and_then(handlers::assign_job)
                    .and(warp::filters::header::optional::<String>(ACCEPT.as_str()))
                    .and_then(prepare_response)
            }

            // POST /api/v1/distserver/submit_toolchain/{job_id: JobId}
            fn submit_toolchain(
                _request_counter: Arc<atomic::AtomicUsize>,
                job_authorizer: Arc<dyn JobAuthorizer>,
                handler: Arc<dyn ServerIncoming>,
                requester: Arc<dyn dist::ServerOutgoing>,
            ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
                warp::path!("api" / "v1" / "distserver" / "submit_toolchain" / JobId)
                    .and(warp::post())
                    .and(with_job_authorizer(job_authorizer))
                    .and(warp::header::headers_cloned())
                    .and_then(authorize)
                    .and(with_server_incoming_handler(handler))
                    .and(with_requester(requester))
                    .and(warp::body::bytes())
                    .and_then(handlers::submit_toolchain)
                    .and(warp::filters::header::optional::<String>(ACCEPT.as_str()))
                    .and_then(prepare_response)
            }

            // POST /api/v1/distserver/run_job/{job_id: JobId}
            fn run_job(
                _request_counter: Arc<atomic::AtomicUsize>,
                job_authorizer: Arc<dyn JobAuthorizer>,
                handler: Arc<dyn ServerIncoming>,
                requester: Arc<dyn dist::ServerOutgoing>,
            ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
                warp::path!("api" / "v1" / "distserver" / "run_job" / JobId)
                    .and(warp::post())
                    .and(with_job_authorizer(job_authorizer))
                    .and(warp::header::headers_cloned())
                    .and_then(authorize)
                    .and(with_server_incoming_handler(handler))
                    .and(with_requester(requester))
                    .and(warp::body::bytes())
                    .and_then(handlers::run_job)
                    .and(warp::filters::header::optional::<String>(ACCEPT.as_str()))
                    .and_then(prepare_response)
            }

            pub fn api(
                job_authorizer: Arc<dyn JobAuthorizer>,
                server_incoming_handler: Arc<dyn ServerIncoming>,
                requester: Arc<dyn dist::ServerOutgoing>,
            ) -> impl Filter<Extract = impl Reply, Error = Infallible> + Clone {
                let request_count = Arc::new(atomic::AtomicUsize::new(0));

                assign_job(
                    request_count.clone(),
                    job_authorizer.clone(),
                    server_incoming_handler.clone(),
                )
                .or(submit_toolchain(
                    request_count.clone(),
                    job_authorizer.clone(),
                    server_incoming_handler.clone(),
                    requester.clone(),
                ))
                .or(run_job(
                    request_count,
                    job_authorizer,
                    server_incoming_handler,
                    requester,
                ))
                .recover(handle_rejection)
            }

            fn make_401_with_body(short_err: &str, body: Option<ClientVisibleMsg>) -> Response {
                let body = reply::with_status(
                    body.map(|b| b.0).unwrap_or_default(),
                    StatusCode::UNAUTHORIZED,
                );

                reply::with_header(
                    body,
                    WWW_AUTHENTICATE,
                    format!("Bearer error=\"{}\"", short_err),
                )
                .into_response()
            }

            fn err_and_log<E: std::error::Error>(err: E, status: StatusCode) -> Response {
                let mut err_msg = err.to_string();
                let mut maybe_cause = err.source();
                while let Some(cause) = maybe_cause {
                    err_msg.push_str(", caused by: ");
                    err_msg.push_str(&cause.to_string());
                    maybe_cause = cause.source();
                }

                warn!("Res error: {}", err_msg);
                let err: Box<dyn std::error::Error> = err.into();
                let json = ErrJson::from_err(&*err);

                reply::with_status(warp::reply::json(&json), status).into_response()
            }

            async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
                if err.is_not_found() {
                    Ok(reply::with_status(warp::reply(), StatusCode::NOT_FOUND).into_response())
                } else if let Some(e) = err.find::<Error>() {
                    match e {
                        Error::AuthorizationHeaderBroken
                        | Error::NoAuthorizationHeader
                        | Error::BearerAuthFailed => {
                            let err: Box<dyn std::error::Error> = e.into();
                            let json = ErrJson::from_err(&*err);
                            Ok(make_401_with_body(
                                "invalid_jwt",
                                Some(ClientVisibleMsg(json.into_data())),
                            )
                            .into_response())
                        }
                        Error::Bincode => Ok(err_and_log(e, StatusCode::BAD_REQUEST)),
                        Error::AssignJob => Ok(err_and_log(e, StatusCode::INTERNAL_SERVER_ERROR)),
                    }
                } else {
                    Ok(
                        warp::reply::with_status(warp::reply(), StatusCode::NOT_FOUND)
                            .into_response(),
                    )
                }
            }

            async fn from_bytes<O>(bytes: bytes::Bytes) -> Result<O, Rejection>
            where
                O: serde::de::DeserializeOwned,
            {
                let a = bincode::deserialize_from::<_, O>(bytes.as_ref())
                    .map_err(|_| Error::Bincode)
                    .map_err(warp::reject::custom)?;

                Ok(a)
            }

            fn toolchain() -> impl Filter<Extract = (dist::Toolchain,), Error = Rejection> + Clone {
                warp::body::bytes().and_then(from_bytes)
            }
        }

        pub(super) mod handlers {
            use super::super::JobId;
            use super::super::RunJobHttpRequest;
            use super::Error;
            use crate::dist::{
                AssignJobResult, InputsReader, RunJobResult, SubmitToolchainResult, ToolchainReader,
            };
            use crate::dist::{ServerIncoming, ServerOutgoing, Toolchain};
            use byteorder::{BigEndian, ReadBytesExt};
            use flate2::read::ZlibDecoder as ZlibReadDecoder;
            use std::sync::Arc;
            use warp::reject::Rejection;

            pub async fn assign_job(
                job_id: JobId,
                toolchain: Toolchain,
                handler: Arc<dyn ServerIncoming>,
                _req_id: usize,
            ) -> Result<AssignJobResult, Rejection> {
                let res = handler
                    .handle_assign_job(job_id, toolchain)
                    .await
                    .map_err(|_| warp::reject::custom(Error::AssignJob))?;

                Ok(res)
            }

            pub async fn submit_toolchain(
                job_id: JobId,
                handler: Arc<dyn ServerIncoming>,
                requester: Arc<dyn ServerOutgoing>,
                body: bytes::Bytes,
            ) -> Result<SubmitToolchainResult, Rejection> {
                let toolchain_rdr = ToolchainReader(Box::new(body.as_ref()));
                let res = handler
                    .handle_submit_toolchain(requester.as_ref(), job_id, toolchain_rdr)
                    .await
                    .map_err(|_| warp::reject::custom(Error::AssignJob))?;

                Ok(res)
            }

            pub async fn run_job(
                job_id: JobId,
                handler: Arc<dyn ServerIncoming>,
                requester: Arc<dyn ServerOutgoing>,
                body: bytes::Bytes,
            ) -> Result<RunJobResult, Rejection> {
                use std::io::Read;

                let mut body = body.as_ref();
                let bincode_length = body
                    .read_u32::<BigEndian>()
                    .map_err(|_| warp::reject::custom(Error::AssignJob))?
                    as u64;

                let mut bincode_reader = body.take(bincode_length);
                let runjob = bincode::deserialize_from(&mut bincode_reader)
                    .map_err(|_| warp::reject::custom(Error::AssignJob))?;

                let RunJobHttpRequest { command, outputs } = runjob;

                let body = bincode_reader.into_inner();

                let inputs_rdr = InputsReader(Box::new(ZlibReadDecoder::new(body)));

                let outputs = outputs.into_iter().collect();

                let res = handler
                    .handle_run_job(requester.as_ref(), job_id, command, outputs, inputs_rdr)
                    .await
                    .map_err(|_| warp::reject::custom(Error::AssignJob))?;

                Ok(res)
            }
        }
    }

    mod scheduler_api_v1 {
        use thiserror::Error;

        pub use filters::api;

        #[derive(Error, Debug)]
        pub enum Error {
            #[error("no Authorization header")]
            NoAuthorizationHeader,
            #[error("authorization header is wrong")]
            AuthorizationHeaderBroken,
            #[error("bearer_auth_failed")]
            BearerAuthFailed,
            #[error("bincode error")]
            Bincode,
            #[error("failed to alloc job")]
            AllocJob,
            #[error("failed to get status")]
            Status,
            #[error("bad request")]
            BadRequest,
            #[error("invalid_bearer_token_mismatched_address")]
            InvalidBearerTokenMismatchedAddress,
            #[error("invalid_bearer_token")]
            InvalidBearerToken,
            #[error("update certs")]
            UpdateCerts,
            #[error("failed to interpret pem as certificate")]
            BadCertificate,
            #[error("failed to create a HTTP client")]
            NoHTTPClient,
            #[error("failed to process heartbeat")]
            Heartbeat,
            #[error("failed to update job state")]
            UpdateJobState,
            #[error("failed to create a http client")]
            ClientBuildFailed,
        }

        impl warp::reject::Reject for Error {}

        pub(super) mod filters {
            use super::super::{
                ClientAuthCheck, ClientVisibleMsg, ErrJson, SchedulerRequester, ServerAuthCheck,
            };
            use super::{handlers, Error};
            use crate::dist;
            use crate::dist::{JobId, ServerId};
            use bytes::Buf;
            use std::collections::HashMap;
            use std::convert::Infallible;
            use std::net::SocketAddr;
            use std::sync::Arc;
            use tokio::sync::Mutex;
            use warp::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
            use warp::{
                http::{
                    header::{HeaderMap, HeaderValue},
                    StatusCode,
                },
                reply::{self, Response},
                Filter, Rejection, Reply,
            };

            fn make_401_with_body(short_err: &str, body: ClientVisibleMsg) -> Response {
                let body = reply::with_status(body.0, StatusCode::UNAUTHORIZED);
                reply::with_header(
                    body,
                    WWW_AUTHENTICATE,
                    format!("Bearer error=\"{}\"", short_err),
                )
                .into_response()
            }

            fn err_and_log<E: std::error::Error>(err: E, status: StatusCode) -> Response {
                let mut err_msg = err.to_string();
                let mut maybe_cause = err.source();
                while let Some(cause) = maybe_cause {
                    err_msg.push_str(", caused by: ");
                    err_msg.push_str(&cause.to_string());
                    maybe_cause = cause.source();
                }

                warn!("Res error: {}", err_msg);
                let err: Box<dyn std::error::Error> = err.into();
                let json = ErrJson::from_err(&*err);

                reply::with_status(warp::reply::json(&json), status).into_response()
            }

            async fn handle_rejection(
                err: Rejection,
            ) -> Result<impl Reply, std::convert::Infallible> {
                if err.is_not_found() {
                    Ok(reply::with_status(warp::reply(), StatusCode::NOT_FOUND).into_response())
                } else if let Some(e) = err.find::<Error>() {
                    match e {
                        Error::NoAuthorizationHeader
                        | Error::BearerAuthFailed
                        | Error::AuthorizationHeaderBroken
                        | Error::InvalidBearerTokenMismatchedAddress
                        | Error::InvalidBearerToken => {
                            let err: Box<dyn std::error::Error> = e.into();
                            let json = ErrJson::from_err(&*err);
                            Ok(make_401_with_body(
                                "invalid_jwt",
                                ClientVisibleMsg(json.into_data()),
                            )
                            .into_response())
                        }
                        Error::Bincode
                        | Error::UpdateCerts
                        | Error::BadRequest
                        | Error::BadCertificate => Ok(err_and_log(e, StatusCode::BAD_REQUEST)),
                        Error::AllocJob
                        | Error::Heartbeat
                        | Error::UpdateJobState
                        | Error::Status
                        | Error::NoHTTPClient
                        | Error::ClientBuildFailed => {
                            Ok(err_and_log(e, StatusCode::INTERNAL_SERVER_ERROR))
                        }
                    }
                } else {
                    Ok(reply::with_status(warp::reply(), StatusCode::NOT_FOUND).into_response())
                }
            }

            pub fn api(
                requester: Arc<SchedulerRequester>,
                auth: Arc<dyn ClientAuthCheck>,
                s: Arc<dyn dist::SchedulerIncoming>,
                certificates: Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
                check_server_auth: ServerAuthCheck,
            ) -> impl Filter<Extract = impl Reply, Error = Infallible> + Clone {
                alloc_job(
                    requester.clone(),
                    auth.clone(),
                    s.clone(),
                    certificates.clone(),
                )
                .or(server_certificate(certificates.clone()))
                .or(heartbeat_server(
                    check_server_auth.clone(),
                    s.clone(),
                    certificates,
                    requester,
                ))
                .or(job_state(check_server_auth, s.clone()))
                .or(status(s))
                .recover(handle_rejection)
            }

            // POST /api/v1/scheduler/alloc_job
            fn alloc_job(
                requester: Arc<SchedulerRequester>,
                auth: Arc<dyn ClientAuthCheck>,
                s: Arc<dyn dist::SchedulerIncoming>,
                certificates: Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
            ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
                warp::path!("api" / "v1" / "scheduler" / "alloc_job")
                    .and(warp::post())
                    .and(with_auth(auth))
                    .untuple_one()
                    .and(with_handler(s))
                    .and(toolchain())
                    .and(with_requester(requester))
                    .and(with_certificates(certificates))
                    .and_then(handlers::alloc_job)
                    .and(warp::filters::header::optional::<String>(ACCEPT.as_str()))
                    .and_then(prepare_response)
            }

            // GET /api/v1/scheduler/server_certificate/{server_id: ServerId})
            fn server_certificate(
                certificates: Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
            ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
                warp::path!("api" / "v1" / "scheduler" / "server_certificate" / ServerId)
                    .and(warp::get())
                    .and(with_certificates(certificates))
                    .and_then(handlers::server_certificate)
                    .and(warp::filters::header::optional::<String>(ACCEPT.as_str()))
                    .and_then(prepare_response)
            }

            // POST /api/v1/scheduler/heartbeat_server
            fn heartbeat_server(
                check_server_auth: ServerAuthCheck,
                s: Arc<dyn dist::SchedulerIncoming>,
                certificates: Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
                requester: Arc<SchedulerRequester>,
            ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
                warp::path!("api" / "v1" / "scheduler" / "heartbeat_server")
                    .and(warp::post())
                    .and(with_server_auth(check_server_auth))
                    .and(warp::header::headers_cloned())
                    .and(warp::addr::remote())
                    .and_then(auth_server)
                    .and(with_handler(s))
                    .and(bincode_input())
                    .and(with_certificates(certificates))
                    .and(with_requester(requester))
                    .and_then(handlers::heartbeat_server)
                    .and(warp::filters::header::optional::<String>(ACCEPT.as_str()))
                    .and_then(prepare_response)
            }

            // POST /api/v1/scheduler/job_state/{job_id: JobId}
            fn job_state(
                check_server_auth: ServerAuthCheck,
                s: Arc<dyn dist::SchedulerIncoming>,
            ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
                warp::path!("api" / "v1" / "scheduler" / "job_state" / JobId)
                    .and(warp::post())
                    .and(
                        with_server_auth(check_server_auth)
                            .and(warp::header::headers_cloned())
                            .and(warp::addr::remote())
                            .and_then(auth_server),
                    )
                    .and(with_handler(s))
                    .and(bincode_input())
                    .and_then(handlers::job_state)
                    .and(warp::filters::header::optional::<String>(ACCEPT.as_str()))
                    .and_then(prepare_response)
            }

            // GET /api/v1/scheduler/status
            fn status(
                s: Arc<dyn dist::SchedulerIncoming>,
            ) -> impl Filter<Extract = (warp::reply::Response,), Error = Rejection> + Clone
            {
                warp::path!("api" / "v1" / "scheduler" / "status")
                    .and(warp::get())
                    .and(with_handler(s))
                    .and_then(handlers::status)
                    .and(warp::filters::header::optional::<String>(ACCEPT.as_str()))
                    .and_then(prepare_response)
            }

            fn bincode_input<T>() -> impl Filter<Extract = (T,), Error = Rejection> + Clone
            where
                T: serde::de::DeserializeOwned + std::marker::Send,
            {
                warp::header::exact_ignore_case(CONTENT_TYPE.as_str(), "application/octet-stream")
                    .and(
                        warp::body::bytes().and_then(|body: bytes::Bytes| async move {
                            let mut reader = body.reader();
                            bincode::deserialize_from::<_, T>(&mut reader)
                                .map_err(|_| warp::reject::custom(Error::Bincode))
                        }),
                    )
            }

            async fn prepare_response<T>(
                content: T,
                accept: Option<String>,
            ) -> Result<warp::reply::Response, Rejection>
            where
                T: serde::Serialize,
            {
                match accept {
                    Some(accept) if accept == "application/json" => {
                        Ok(warp::reply::json(&content).into_response())
                    }
                    _ => Ok(warp::http::Response::builder()
                        .header(CONTENT_TYPE, "application/octet-stream")
                        .body(hyper::Body::from(
                            bincode::serialize(&content).map_err(|_| Error::Bincode)?,
                        ))
                        .map_err(|_| Error::Bincode)?),
                }
            }

            fn with_handler(
                handler: Arc<dyn dist::SchedulerIncoming>,
            ) -> impl Filter<Extract = (Arc<dyn dist::SchedulerIncoming>,), Error = Infallible> + Clone
            {
                warp::any().map(move || handler.clone())
            }

            fn with_requester(
                requester: Arc<SchedulerRequester>,
            ) -> impl Filter<Extract = (Arc<SchedulerRequester>,), Error = Infallible> + Clone
            {
                warp::any().map(move || requester.clone())
            }

            fn with_certificates(
                certificates: Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
            ) -> impl Filter<
                Extract = (Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,),
                Error = Infallible,
            > + Clone {
                warp::any().map(move || certificates.clone())
            }

            fn with_server_auth(
                check_server_auth: ServerAuthCheck,
            ) -> impl Filter<Extract = (ServerAuthCheck,), Error = Infallible> + Clone {
                warp::any().map(move || check_server_auth.clone())
            }

            fn with_auth(
                auth: Arc<dyn ClientAuthCheck>,
            ) -> impl Filter<Extract = ((),), Error = Rejection> + Clone {
                warp::header::headers_cloned()
                    .map(move |headers: HeaderMap<HeaderValue>| (auth.clone(), headers))
                    .untuple_one()
                    .and_then(authorize)
            }

            fn bearer_http_auth(headers: &HeaderMap<HeaderValue>) -> Result<String, Error> {
                let header = headers
                    .get(AUTHORIZATION)
                    .ok_or(Error::NoAuthorizationHeader)?;

                let header = header
                    .to_str()
                    .map_err(|_| Error::AuthorizationHeaderBroken)?;

                let mut split = header.splitn(2, |c| c == ' ');

                let authtype = split.next().ok_or(Error::AuthorizationHeaderBroken)?;

                if authtype != "Bearer" {
                    return Err(Error::AuthorizationHeaderBroken);
                }

                Ok(split
                    .next()
                    .ok_or(Error::AuthorizationHeaderBroken)?
                    .to_string())
            }

            async fn authorize(
                check_client_auth: Arc<dyn ClientAuthCheck>,
                headers: HeaderMap<HeaderValue>,
            ) -> Result<(), Rejection> {
                let bearer_auth = bearer_http_auth(&headers)?;

                check_client_auth
                    .check(&bearer_auth)
                    .await
                    .map_err(|_| Error::BearerAuthFailed)?;

                Ok(())
            }

            async fn auth_server(
                check_server_auth: ServerAuthCheck,
                headers: HeaderMap<HeaderValue>,
                remote: Option<SocketAddr>,
            ) -> Result<ServerId, Rejection> {
                match check_server_auth(&bearer_http_auth(&headers)?) {
                    Some(server_id) => {
                        let origin_ip = if let Some(header_val) = headers.get("X-Real-IP") {
                            trace!("X-Real-IP: {:?}", header_val);
                            match header_val.to_str().unwrap().parse() {
                                Ok(ip) => ip,
                                Err(err) => {
                                    warn!(
                                        "X-Real-IP value {:?} could not be parsed: {:?}",
                                        header_val, err
                                    );
                                    return Err(warp::reject::custom(Error::BadRequest));
                                }
                            }
                        } else {
                            remote.unwrap().ip()
                        };

                        if server_id.addr().ip() != origin_ip {
                            trace!("server ip: {:?}", server_id.addr().ip());
                            trace!("request ip: {:?}", remote.unwrap().ip());
                            Err(warp::reject::custom(
                                Error::InvalidBearerTokenMismatchedAddress,
                            ))
                        } else {
                            Ok(server_id)
                        }
                    }
                    None => Err(warp::reject::custom(Error::InvalidBearerToken)),
                }
            }

            async fn from_bytes<O>(bytes: bytes::Bytes) -> Result<O, Rejection>
            where
                O: serde::de::DeserializeOwned,
            {
                let a = bincode::deserialize_from::<_, O>(bytes.as_ref())
                    .map_err(|_| Error::Bincode)
                    .map_err(warp::reject::custom)?;

                Ok(a)
            }

            fn toolchain() -> impl Filter<Extract = (dist::Toolchain,), Error = Rejection> + Clone {
                warp::body::bytes().and_then(from_bytes)
            }
        }

        pub(super) mod handlers {
            use super::super::AllocJobHttpResponse;
            use super::super::{HeartbeatServerHttpRequest, ServerCertificateHttpResponse};
            use super::super::{JWTJobAuthorizer, JobId, SchedulerRequester};
            use super::Error;
            use crate::dist::{self, ServerId};
            use crate::dist::{
                HeartbeatServerResult, JobState, SchedulerStatusResult, UpdateJobStateResult,
            };
            use std::collections::HashMap;
            use std::sync::Arc;
            use tokio::sync::Mutex;
            use warp::reject::{self, Rejection};

            pub async fn alloc_job(
                handler: Arc<dyn dist::SchedulerIncoming>,
                toolchain: dist::Toolchain,
                requester: Arc<SchedulerRequester>,
                certs: Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
            ) -> Result<AllocJobHttpResponse, Rejection> {
                let alloc_job_res = handler
                    .handle_alloc_job(requester.as_ref(), toolchain)
                    .await
                    .map_err(|_| reject::custom(Error::AllocJob))?;

                let certs = certs.lock().await;
                let res = AllocJobHttpResponse::from_alloc_job_result(alloc_job_res, &certs);

                Ok(res)
            }

            pub async fn server_certificate(
                server_id: ServerId,
                certificates: Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
            ) -> Result<ServerCertificateHttpResponse, Rejection> {
                let certs = certificates.lock().await;

                let (cert_digest, cert_pem) = certs.get(&server_id).cloned().unwrap();
                let res = ServerCertificateHttpResponse {
                    cert_digest,
                    cert_pem,
                };

                Ok(res)
            }

            pub async fn heartbeat_server(
                server_id: ServerId,
                handler: Arc<dyn dist::SchedulerIncoming>,
                heartbeat_server: HeartbeatServerHttpRequest,
                server_certificates: Arc<Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>>>,
                requester: Arc<SchedulerRequester>,
            ) -> Result<HeartbeatServerResult, Rejection> {
                let HeartbeatServerHttpRequest {
                    num_cpus,
                    jwt_key,
                    server_nonce,
                    cert_digest,
                    cert_pem,
                } = heartbeat_server;

                let mut client = requester.client.lock().await;
                let mut certs = server_certificates.lock().await;
                maybe_update_certs(&mut *client, &mut certs, server_id, cert_digest, cert_pem)
                    .await
                    .map_err(|_| Error::UpdateCerts)?;

                let job_authorizer = Box::new(JWTJobAuthorizer::new(jwt_key));
                let res: HeartbeatServerResult = handler
                    .handle_heartbeat_server(server_id, server_nonce, num_cpus, job_authorizer)
                    .map_err(|_| Error::Heartbeat)?;

                Ok(res)
            }

            pub async fn job_state(
                job_id: JobId,
                server_id: ServerId,
                handler: Arc<dyn dist::SchedulerIncoming>,
                job_state: JobState,
            ) -> Result<UpdateJobStateResult, Rejection> {
                let res = handler
                    .handle_update_job_state(job_id, server_id, job_state)
                    .map_err(|_| Error::UpdateJobState)?;

                Ok(res)
            }

            pub async fn status(
                handler: Arc<dyn dist::SchedulerIncoming>,
            ) -> Result<SchedulerStatusResult, Rejection> {
                let res: SchedulerStatusResult =
                    handler.handle_status().map_err(|_| Error::Status)?;
                Ok(res)
            }

            async fn maybe_update_certs(
                client: &mut reqwest::Client,
                certs: &mut HashMap<ServerId, (Vec<u8>, Vec<u8>)>,
                server_id: ServerId,
                cert_digest: Vec<u8>,
                cert_pem: Vec<u8>,
            ) -> Result<(), Error> {
                if let Some((saved_cert_digest, _)) = certs.get(&server_id) {
                    if saved_cert_digest == &cert_digest {
                        return Ok(());
                    }
                }
                info!(
                    "Adding new certificate for {} to scheduler",
                    server_id.addr()
                );

                let mut client_builder = crate::util::native_tls_no_sni_client_builder()
                    .map_err(|_| Error::ClientBuildFailed)?;
                // Add all the certificates we know about
                client_builder = client_builder.add_root_certificate(
                    reqwest::Certificate::from_pem(&cert_pem).map_err(|_| Error::BadCertificate)?,
                );
                for (_, cert_pem) in certs.values() {
                    client_builder = client_builder.add_root_certificate(
                        reqwest::Certificate::from_pem(cert_pem).expect("previously valid cert"),
                    );
                }
                // Finish the clients
                let new_client = client_builder.build().map_err(|_| Error::NoHTTPClient)?;
                // Use the updated certificates
                *client = new_client;
                certs.insert(server_id, (cert_digest, cert_pem));
                Ok(())
            }
        }
    }

    pub struct Scheduler<S> {
        public_addr: SocketAddr,
        handler: S,
        // Is this client permitted to use the scheduler?
        check_client_auth: Box<dyn ClientAuthCheck>,
        // Do we believe the server is who they appear to be?
        check_server_auth: ServerAuthCheck,
    }

    impl<S: dist::SchedulerIncoming + 'static> Scheduler<S> {
        pub fn new(
            public_addr: SocketAddr,
            handler: S,
            check_client_auth: Box<dyn ClientAuthCheck>,
            check_server_auth: ServerAuthCheck,
        ) -> Self {
            Self {
                public_addr,
                handler,
                check_client_auth,
                check_server_auth,
            }
        }

        pub async fn start(self) -> Result<Void> {
            let Self {
                public_addr,
                handler,
                check_client_auth,
                check_server_auth,
            } = self;

            let client = crate::util::native_tls_no_sni_client_builder()
                .unwrap()
                .build()
                .unwrap();
            let requester = Arc::new(SchedulerRequester {
                client: Mutex::new(client),
            });

            let check_client_auth = Arc::from(check_client_auth);
            let handler = Arc::from(handler);
            let server_certificates = Arc::new(Mutex::new(HashMap::new()));
            let api = scheduler_api_v1::api(
                requester,
                check_client_auth,
                handler,
                server_certificates,
                check_server_auth,
            );
            info!("Scheduler listening for clients on {}", public_addr);
            warp::serve(api).run(public_addr).await;

            panic!("Warp server terminated")
        }
    }
    pub struct SchedulerRequester {
        client: tokio::sync::Mutex<reqwest::Client>,
    }

    #[async_trait]
    impl dist::SchedulerOutgoing for SchedulerRequester {
        async fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            tc: Toolchain,
            auth: String,
        ) -> Result<AssignJobResult> {
            let url = urls::server_assign_job(server_id, job_id);
            let req = self.client.lock().await.post(url);
            bincode_req(req.bearer_auth(auth).bincode(&tc)?)
                .await
                .context("POST to scheduler assign_job failed")
        }
    }

    pub struct Server<S> {
        public_addr: SocketAddr,
        scheduler_url: reqwest::Url,
        scheduler_auth: String,
        // HTTPS pieces all the builders will use for connection encryption
        cert_digest: Vec<u8>,
        cert_pem: Vec<u8>,
        privkey_pem: Vec<u8>,
        // Key used to sign any requests relating to jobs
        jwt_key: Vec<u8>,
        // Randomly generated nonce to allow the scheduler to detect server restarts
        server_nonce: ServerNonce,
        handler: S,
    }

    impl<S: dist::ServerIncoming + 'static> Server<S> {
        pub fn new(
            public_addr: SocketAddr,
            scheduler_url: reqwest::Url,
            scheduler_auth: String,
            handler: S,
        ) -> Result<Self> {
            let (cert_digest, cert_pem, privkey_pem) =
                create_https_cert_and_privkey(public_addr)
                    .context("failed to create HTTPS certificate for server")?;
            let mut jwt_key = vec![0; JWT_KEY_LENGTH];
            OsRng.fill_bytes(&mut jwt_key);
            let server_nonce = ServerNonce::new();

            Ok(Self {
                public_addr,
                scheduler_url,
                scheduler_auth,
                cert_digest,
                cert_pem,
                privkey_pem,
                jwt_key,
                server_nonce,
                handler,
            })
        }

        pub async fn start(self) -> Result<Void> {
            let Self {
                public_addr,
                scheduler_url,
                scheduler_auth,
                cert_digest,
                cert_pem,
                privkey_pem,
                jwt_key,
                server_nonce,
                handler,
            } = self;

            let handler = Arc::new(handler);

            let heartbeat_req = HeartbeatServerHttpRequest {
                num_cpus: num_cpus::get(),
                jwt_key: jwt_key.clone(),
                server_nonce,
                cert_digest,
                cert_pem: cert_pem.clone(),
            };
            let job_authorizer = Arc::new(JWTJobAuthorizer::new(jwt_key));
            let heartbeat_url = urls::scheduler_heartbeat_server(&scheduler_url);
            let requester = Arc::new(ServerRequester {
                client: reqwest::Client::new(),
                scheduler_url,
                scheduler_auth: scheduler_auth.clone(),
            });

            let api = distserver_api_v1::api(job_authorizer, handler, requester);

            tokio::spawn(async move {
                use tokio::time;

                let client = reqwest::Client::new();
                loop {
                    trace!("Performing hearbeat");
                    match bincode_req(
                        client
                            .post(heartbeat_url.clone())
                            .bearer_auth(scheduler_auth.clone())
                            .bincode(&heartbeat_req)
                            .expect("failed to serialize a heartbeat"),
                    )
                    .await
                    {
                        Ok(HeartbeatServerResult { is_new }) => {
                            trace!("Heartbeat success is_new={}", is_new);
                            // TODO: if is_new, terminate all running jobs
                            time::sleep(HEARTBEAT_INTERVAL).await;
                        }
                        Err(e) => {
                            error!("Failed to send heartbeat to server: {}", e);
                            time::sleep(HEARTBEAT_ERROR_INTERVAL).await;
                        }
                    }
                }
            });

            warp::serve(api)
                .tls()
                .cert(cert_pem)
                .key(privkey_pem)
                .run(public_addr)
                .await;

            panic!("Warp server terminated")
        }
    }

    struct ServerRequester {
        client: reqwest::Client,
        scheduler_url: reqwest::Url,
        scheduler_auth: String,
    }

    #[async_trait]
    impl dist::ServerOutgoing for ServerRequester {
        async fn do_update_job_state(
            &self,
            job_id: JobId,
            state: JobState,
        ) -> Result<UpdateJobStateResult> {
            let url = urls::scheduler_job_state(&self.scheduler_url, job_id);
            bincode_req(
                self.client
                    .post(url)
                    .bearer_auth(self.scheduler_auth.clone())
                    .bincode(&state)?,
            )
            .await
            .context("POST to scheduler job_state failed")
        }
    }
}

#[cfg(feature = "dist-client")]
mod client {
    use super::super::cache;
    use crate::config;
    use crate::dist::pkg::{InputsPackager, ToolchainPackager};
    use crate::dist::{
        self, AllocJobResult, CompileCommand, JobAlloc, PathTransformer, RunJobResult,
        SchedulerStatusResult, SubmitToolchainResult, Toolchain,
    };

    use byteorder::{BigEndian, WriteBytesExt};
    use flate2::write::ZlibEncoder as ZlibWriteEncoder;
    use flate2::Compression;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    use super::common::{
        bincode_req, AllocJobHttpResponse, ReqwestRequestBuilderExt, RunJobHttpRequest,
        ServerCertificateHttpResponse,
    };
    use super::urls;
    use crate::errors::*;

    const REQUEST_TIMEOUT_SECS: u64 = 600;
    const CONNECT_TIMEOUT_SECS: u64 = 5;

    pub struct Client {
        auth_token: String,
        scheduler_url: reqwest::Url,
        // cert_digest -> cert_pem
        server_certs: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
        client_async: Arc<Mutex<reqwest::Client>>,
        pool: tokio::runtime::Handle,
        tc_cache: Arc<cache::ClientToolchains>,
        rewrite_includes_only: bool,
    }

    impl Client {
        pub fn new(
            pool: &tokio::runtime::Handle,
            scheduler_url: reqwest::Url,
            cache_dir: &Path,
            cache_size: u64,
            toolchain_configs: &[config::DistToolchainConfig],
            auth_token: String,
            rewrite_includes_only: bool,
        ) -> Result<Self> {
            let timeout = Duration::new(REQUEST_TIMEOUT_SECS, 0);
            let connect_timeout = Duration::new(CONNECT_TIMEOUT_SECS, 0);

            let builder = crate::util::native_tls_no_sni_client_builder()
                .context("failed to create an async HTTP client")?;

            let client_async = builder
                .timeout(timeout)
                .connect_timeout(connect_timeout)
                .build()
                .context("failed to create an async HTTP client")?;
            let client_toolchains =
                cache::ClientToolchains::new(cache_dir, cache_size, toolchain_configs)
                    .context("failed to initialise client toolchains")?;
            Ok(Self {
                auth_token,
                scheduler_url,
                server_certs: Default::default(),
                client_async: Arc::new(Mutex::new(client_async)),
                pool: pool.clone(),
                tc_cache: Arc::new(client_toolchains),
                rewrite_includes_only,
            })
        }

        fn update_certs(
            client_async: &mut reqwest::Client,
            certs: &mut HashMap<Vec<u8>, Vec<u8>>,
            cert_digest: Vec<u8>,
            cert_pem: Vec<u8>,
        ) -> Result<()> {
            let mut client_async_builder = crate::util::native_tls_no_sni_client_builder()
                .context("failed to create an async HTTP client")?;

            // Add all the certificates we know about
            client_async_builder = client_async_builder.add_root_certificate(
                reqwest::Certificate::from_pem(&cert_pem)
                    .context("failed to interpret pem as certificate")?,
            );
            for cert_pem in certs.values() {
                client_async_builder = client_async_builder.add_root_certificate(
                    reqwest::Certificate::from_pem(cert_pem).expect("previously valid cert"),
                );
            }
            // Finish the clients
            let timeout = Duration::new(REQUEST_TIMEOUT_SECS, 0);
            let new_client_async = client_async_builder
                .timeout(timeout)
                .build()
                .context("failed to create an async HTTP client")?;
            // Use the updated certificates
            *client_async = new_client_async;
            certs.insert(cert_digest, cert_pem);
            Ok(())
        }
    }

    #[async_trait]
    impl dist::Client for Client {
        async fn do_alloc_job(&self, tc: Toolchain) -> Result<AllocJobResult> {
            let scheduler_url = self.scheduler_url.clone();
            let url = urls::scheduler_alloc_job(&scheduler_url);
            let mut req = self.client_async.lock().await.post(url);
            req = req.bearer_auth(self.auth_token.clone()).bincode(&tc)?;

            let client_async = self.client_async.clone();
            let server_certs = self.server_certs.clone();

            match bincode_req(req).await? {
                AllocJobHttpResponse::Success {
                    job_alloc,
                    need_toolchain,
                    cert_digest,
                } => {
                    let server_id = job_alloc.server_id;
                    let alloc_job_res = Ok(AllocJobResult::Success {
                        job_alloc,
                        need_toolchain,
                    });
                    if server_certs.lock().await.contains_key(&cert_digest) {
                        return alloc_job_res;
                    }
                    info!(
                        "Need to request new certificate for server {}",
                        server_id.addr()
                    );
                    let url = urls::scheduler_server_certificate(&scheduler_url, server_id);
                    let req = client_async.lock().await.get(url);
                    let res: ServerCertificateHttpResponse = bincode_req(req)
                        .await
                        .context("GET to scheduler server_certificate failed")?;

                    Self::update_certs(
                        &mut *client_async.lock().await,
                        &mut *server_certs.lock().await,
                        res.cert_digest,
                        res.cert_pem,
                    )
                    .unwrap_or_else(|e| warn!("Failed to update certificate: {:?}", e));

                    alloc_job_res
                }
                AllocJobHttpResponse::Fail { msg } => Ok(AllocJobResult::Fail { msg }),
            }
        }

        async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
            let scheduler_url = self.scheduler_url.clone();
            let url = urls::scheduler_status(&scheduler_url);
            let req = self.client_async.lock().await.get(url);

            bincode_req(req).await
        }

        async fn do_submit_toolchain(
            &self,
            job_alloc: JobAlloc,
            tc: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            match self.tc_cache.get_toolchain(&tc) {
                Ok(Some(toolchain_file)) => {
                    let url = urls::server_submit_toolchain(job_alloc.server_id, job_alloc.job_id);
                    let req = self.client_async.lock().await.post(url);

                    let _toolchain_file_exists = toolchain_file.metadata()?;

                    use tokio_util::codec::{BytesCodec, FramedRead};
                    let toolchain_file = toolchain_file.into_parts().0;
                    let toolchain_file = tokio::fs::File::from_std(toolchain_file);
                    let stream = FramedRead::new(toolchain_file, BytesCodec::new());

                    let body = reqwest::Body::wrap_stream(stream);

                    let req = req.bearer_auth(job_alloc.auth).body(body);
                    bincode_req(req).await
                }
                Ok(None) => Err(anyhow!("couldn't find toolchain locally")),
                Err(e) => Err(e),
            }
        }

        async fn do_run_job(
            &self,
            job_alloc: JobAlloc,
            command: CompileCommand,
            outputs: Vec<String>,
            inputs_packager: Box<dyn InputsPackager>,
        ) -> Result<(RunJobResult, PathTransformer)> {
            let url = urls::server_run_job(job_alloc.server_id, job_alloc.job_id);
            let req = self.client_async.lock().await.post(url);

            let (path_transformer, compressed_body) = self
                .pool
                .spawn_blocking(move || {
                    let bincode = bincode::serialize(&RunJobHttpRequest { command, outputs })
                        .context("failed to serialize run job request")?;
                    let bincode_length = bincode.len();

                    let mut body = vec![];
                    body.write_u32::<BigEndian>(bincode_length as u32)
                        .expect("Infallible write of bincode length to vec failed");
                    body.write_all(&bincode)
                        .expect("Infallible write of bincode body to vec failed");
                    let path_transformer;
                    {
                        let mut compressor = ZlibWriteEncoder::new(&mut body, Compression::fast());
                        path_transformer = inputs_packager
                            .write_inputs(&mut compressor)
                            .context("Could not write inputs for compilation")?;
                        compressor.flush().context("failed to flush compressor")?;
                        trace!(
                            "Compressed inputs from {} -> {}",
                            compressor.total_in(),
                            compressor.total_out()
                        );
                        compressor.finish().context("failed to finish compressor")?;
                    }

                    ::core::result::Result::<_, anyhow::Error>::Ok((path_transformer, body))
                })
                .await??;

            let req = req
                .bearer_auth(job_alloc.auth.clone())
                .bytes(compressed_body);
            let res = bincode_req(req).await?;

            Ok((res, path_transformer))
        }

        async fn put_toolchain(
            &self,
            compiler_path: PathBuf,
            weak_key: String,
            toolchain_packager: Box<dyn ToolchainPackager>,
        ) -> Result<(Toolchain, Option<(String, PathBuf)>)> {
            let compiler_path = compiler_path.to_owned();
            let weak_key = weak_key.to_owned();
            let tc_cache = self.tc_cache.clone();

            self.pool
                .spawn_blocking(move || {
                    tc_cache.put_toolchain(&compiler_path, &weak_key, toolchain_packager)
                })
                .await?
        }

        fn rewrite_includes_only(&self) -> bool {
            self.rewrite_includes_only
        }
        fn get_custom_toolchain(&self, exe: &Path) -> Option<PathBuf> {
            match self.tc_cache.get_custom_toolchain(exe) {
                Some(Ok((_, _, path))) => Some(path),
                _ => None,
            }
        }
    }
}

#[cfg(all(test, feature = "vs_openssl"))]
mod tests {
    use crate::dist::http::server::create_https_cert_and_privkey;
    use crate::dist::SocketAddr;
    use anyhow::{Context, Result};

    fn legacy_create_https_cert_and_privkey(
        addr: SocketAddr,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let rsa_key = openssl::rsa::Rsa::<openssl::pkey::Private>::generate(2048)
            .context("failed to generate rsa privkey")?;
        let privkey_pem = rsa_key
            .private_key_to_pem()
            .context("failed to create pem from rsa privkey")?;
        let privkey: openssl::pkey::PKey<openssl::pkey::Private> =
            openssl::pkey::PKey::from_rsa(rsa_key)
                .context("failed to create openssl pkey from rsa privkey")?;
        let mut builder =
            openssl::x509::X509::builder().context("failed to create x509 builder")?;

        // Populate the certificate with the necessary parts, mostly from
        // mkcert in openssl
        builder
            .set_version(2)
            .context("failed to set x509 version")?;
        let serial_number = openssl::bn::BigNum::from_u32(1)
            .and_then(|bn| bn.to_asn1_integer())
            .context("failed to create openssl asn1 0")?;
        builder
            .set_serial_number(serial_number.as_ref())
            .context("failed to set x509 serial number")?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)
            .context("failed to create openssl not before asn1")?;
        builder
            .set_not_before(not_before.as_ref())
            .context("failed to set not before on x509")?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365)
            .context("failed to create openssl not after asn1")?;
        builder
            .set_not_after(not_after.as_ref())
            .context("failed to set not after on x509")?;
        builder
            .set_pubkey(privkey.as_ref())
            .context("failed to set pubkey for x509")?;

        let mut name = openssl::x509::X509Name::builder()?;
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &addr.to_string())?;
        let name = name.build();

        builder
            .set_subject_name(&name)
            .context("failed to set subject name")?;
        builder
            .set_issuer_name(&name)
            .context("failed to set issuer name")?;

        // Add the SubjectAlternativeName
        let extension = openssl::x509::extension::SubjectAlternativeName::new()
            .ip(&addr.ip().to_string())
            .build(&builder.x509v3_context(None, None))
            .context("failed to build SAN extension for x509")?;
        builder
            .append_extension(extension)
            .context("failed to append SAN extension for x509")?;

        // Add ExtendedKeyUsage
        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .server_auth()
            .build()
            .context("failed to build EKU extension for x509")?;
        builder
            .append_extension(ext_key_usage)
            .context("failes to append EKU extension for x509")?;

        // Finish the certificate
        builder
            .sign(&privkey, openssl::hash::MessageDigest::sha1())
            .context("failed to sign x509 with sha1")?;
        let cert: openssl::x509::X509 = builder.build();
        let cert_pem = cert.to_pem().context("failed to create pem from x509")?;
        let cert_digest = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .context("failed to create digest of x509 certificate")?
            .as_ref()
            .to_owned();

        Ok((cert_digest, cert_pem, privkey_pem))
    }

    macro_rules! timeit {
        ($work:expr) => {{
            let start = ::std::time::Instant::now();
            let x = { $work };
            eprintln!("took: {:#?}", start.elapsed());
            x
        }};
    }

    #[test]
    fn create_cert_and_sk() {
        let addr = "242.11.9.38:29114".parse().unwrap();

        struct Triple {
            pub cert_digest: Vec<u8>,
            pub cert_pem: Vec<u8>,
            pub privkey_pem: Vec<u8>,
        }

        impl From<(Vec<u8>, Vec<u8>, Vec<u8>)> for Triple {
            fn from((cert_digest, cert_pem, privkey_pem): (Vec<u8>, Vec<u8>, Vec<u8>)) -> Self {
                Self {
                    cert_digest,
                    cert_pem,
                    privkey_pem,
                }
            }
        }

        struct PersistOnPanic(Option<tempfile::NamedTempFile>);
        impl Drop for PersistOnPanic {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    std::mem::forget(self.0.take());
                }
            }
        }

        let parse_and_dump_cert = |tag: &'static str, mut data: &[u8]| {
            use std::io::Write;
            let pem = picky::pem::Pem::read_from(&mut data).expect("PEM must be valid. Q.E.D.");
            let mut tempfile = tempfile::Builder::new()
                .prefix(tag)
                .suffix(".cert.pem")
                .tempfile()
                .ok();
            if let Some(tempfile) = tempfile.as_mut() {
                println!("Writing '{}' cert to {}", tag, tempfile.path().display());
                tempfile.write_all(pem.to_string().as_bytes()).unwrap();
            }

            let cert = picky::x509::Cert::from_pem(&pem).expect("Cert from PEM must be ok. Q.E.D.");
            (cert, PersistOnPanic(tempfile))
        };

        let generated: Triple = timeit!(create_https_cert_and_privkey(addr)).unwrap().into();
        let expected: Triple = timeit!(legacy_create_https_cert_and_privkey(addr))
            .unwrap()
            .into();
        // cert
        {
            let (expected_cert, _file) = parse_and_dump_cert("exp", &expected.cert_pem);
            let (generated_cert, _file) = parse_and_dump_cert("gen", &generated.cert_pem);

            // XXX the openssl generated certificate lacks the type
            // XXX which shouldn't be the case, so we accept this
            // assert_eq!(expected_cert.ty(), generated_cert.ty());
            assert_eq!(
                expected_cert.serial_number(),
                generated_cert.serial_number()
            );
            assert_eq!(
                expected_cert.signature_algorithm(),
                generated_cert.signature_algorithm()
            );
            assert_eq!(expected_cert.subject_name(), generated_cert.subject_name());
            assert_eq!(expected_cert.issuer_name(), generated_cert.issuer_name());

            // XXX openssl does not encode i.e. `BasicConstraints` if they match the default,
            // XXX where picky does.
            // XXX As such just checking if all the openssl generated ones are present in the
            // XXX picky generated ones is alright. The vice versa is not necesarily true.
            for expected_ext in expected_cert.extensions() {
                assert_matches::assert_matches!(generated_cert.extensions().iter().find(|generated_ext| { generated_ext.extn_id() == expected_ext.extn_id() }), Some(generated_ext) => {
                    assert_eq!(expected_ext.extn_value(), generated_ext.extn_value(), "Values of extensions are equal");
                });
            }
        }
    }
}
