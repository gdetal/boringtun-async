use std::net::SocketAddr;

use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use ip_network::IpNetwork;

use crate::keys;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("api closed")]
    ApiClosed(#[from] mpsc::SendError),
    #[error("reply channel canceled")]
    ChannelClosed(#[from] oneshot::Canceled),
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Key error")]
    Key(#[from] keys::KeyParseError),
    #[error("error: {0}")]
    Other(String),
}

impl From<&str> for ApiError {
    fn from(value: &str) -> Self {
        Self::Other(value.to_owned())
    }
}

pub type ApiResult = Result<(), ApiError>;

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

pub(crate) struct ApiRequest {
    pub(crate) msg: ApiMessage,
    channel: oneshot::Sender<ApiResult>,
}

impl ApiRequest {
    pub(crate) fn new(msg: ApiMessage) -> (Self, oneshot::Receiver<ApiResult>) {
        let (channel, receiver) = oneshot::channel();

        (Self { msg, channel }, receiver)
    }
}

pub(crate) struct ApiReplier(Option<oneshot::Sender<ApiResult>>);

impl ApiReplier {
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

#[derive(Clone)]
pub struct ApiChannel(mpsc::Sender<ApiRequest>);

impl ApiChannel {
    pub(crate) fn new(channel: mpsc::Sender<ApiRequest>) -> Self {
        Self(channel)
    }

    pub async fn private_key<K>(mut self, key: K) -> ApiResult
    where
        K: TryInto<keys::PrivateKey, Error = keys::KeyParseError>,
    {
        let (req, recv) = ApiRequest::new(ApiMessage::PrivateKey(key.try_into()?.into()));
        self.0.send(req).await?;
        recv.await?
    }

    pub async fn listen_port(&mut self, port: u16) -> ApiResult {
        let (req, recv) = ApiRequest::new(ApiMessage::ListenPort(port));
        self.0.send(req).await?;
        recv.await?
    }

    pub async fn add_peer<K>(
        &mut self,
        public_key: K,
        endpoint: SocketAddr,
        allowed_ips: Vec<ip_network::IpNetwork>,
    ) -> ApiResult
    where
        K: TryInto<keys::PublicKey, Error = keys::KeyParseError>,
    {
        let (req, recv) = ApiRequest::new(ApiMessage::PeerAdd {
            public_key: public_key.try_into()?.into(),
            endpoint,
            allowed_ips,
        });
        self.0.send(req).await?;
        recv.await?
    }

    pub async fn replace_peers(&mut self) -> ApiResult {
        let (req, recv) = ApiRequest::new(ApiMessage::PeerFlush);
        self.0.send(req).await?;
        recv.await?
    }
}
