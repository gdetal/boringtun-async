use boringtun::x25519::{self, PublicKey, StaticSecret};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use ip_network::IpNetwork;
use std::net::SocketAddr;

/// Error types that can occur in the API.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("api closed")]
    ApiClosed(#[from] mpsc::SendError),
    #[error("reply channel canceled")]
    ChannelClosed(#[from] oneshot::Canceled),
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("error: {0}")]
    Other(String),
}

impl From<&str> for ApiError {
    fn from(value: &str) -> Self {
        Self::Other(value.to_owned())
    }
}

/// Result type for API operations.
pub type ApiResult = Result<(), ApiError>;

/// Messages that can be sent to the API.
pub(crate) enum ApiMessage {
    PrivateKey(StaticSecret),
    ListenPort(u16),
    PeerFlush,
    PeerAdd {
        public_key: PublicKey,
        endpoint: SocketAddr,
        allowed_ips: Vec<IpNetwork>,
    },
}

/// Represents a request to the API.
pub(crate) struct ApiRequest {
    pub(crate) msg: ApiMessage,
    channel: oneshot::Sender<ApiResult>,
}

impl ApiRequest {
    /// Creates a new API request.
    pub(crate) fn new(msg: ApiMessage) -> (Self, oneshot::Receiver<ApiResult>) {
        let (channel, receiver) = oneshot::channel();

        (Self { msg, channel }, receiver)
    }
}

/// Represents a replier for API requests.
pub(crate) struct ApiReplier(Option<oneshot::Sender<ApiResult>>);

impl ApiReplier {
    /// Sends a reply for an API request.
    pub(crate) fn reply<T, E: Into<ApiError>>(&mut self, res: Result<T, E>) {
        if let Some(replier) = self.0.take() {
            replier.send(res.map(|_| ()).map_err(|e| e.into())).ok();
        }
    }
}

impl Drop for ApiReplier {
    fn drop(&mut self) {
        // Assume OK:
        self.reply(Ok::<_, ApiError>(()))
    }
}

impl From<ApiRequest> for (ApiMessage, ApiReplier) {
    fn from(val: ApiRequest) -> Self {
        (val.msg, ApiReplier(Some(val.channel)))
    }
}

/// Represents a channel for communicating with the API.
#[derive(Clone)]
pub struct ApiChannel(mpsc::Sender<ApiRequest>);

impl ApiChannel {
    /// Creates a new API channel.
    pub(crate) fn new(channel: mpsc::Sender<ApiRequest>) -> Self {
        Self(channel)
    }

    /// Sets the private key for the API.
    pub async fn private_key<K>(mut self, key: K) -> ApiResult
    where
        K: Into<x25519::StaticSecret>,
    {
        let (req, recv) = ApiRequest::new(ApiMessage::PrivateKey(key.into()));
        self.0.send(req).await?;
        recv.await?
    }

    /// Sets the listen port for the API.
    pub async fn listen_port(&mut self, port: u16) -> ApiResult {
        let (req, recv) = ApiRequest::new(ApiMessage::ListenPort(port));
        self.0.send(req).await?;
        recv.await?
    }

    /// Adds a peer to the API.
    pub async fn add_peer<K>(
        &mut self,
        public_key: K,
        endpoint: SocketAddr,
        allowed_ips: Vec<ip_network::IpNetwork>,
    ) -> ApiResult
    where
        K: Into<x25519::PublicKey>,
    {
        let (req, recv) = ApiRequest::new(ApiMessage::PeerAdd {
            public_key: public_key.into(),
            endpoint,
            allowed_ips,
        });
        self.0.send(req).await?;
        recv.await?
    }

    /// Replaces all peers in the API.
    pub async fn replace_peers(&mut self) -> ApiResult {
        let (req, recv) = ApiRequest::new(ApiMessage::PeerFlush);
        self.0.send(req).await?;
        recv.await?
    }
}
