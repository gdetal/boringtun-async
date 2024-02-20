use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(unix)]
use std::os::fd::RawFd;

use async_compat::Compat;
use boringtun::x25519::StaticSecret;
use futures::{AsyncRead, AsyncWrite, Future, FutureExt, Sink, Stream, StreamExt};
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    api,
    keys::{KeyParseError, PrivateKey},
    packet::Packet,
    Device, Tunnel,
};

#[derive(Debug, thiserror::Error)]
pub enum TunnelBuilderError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Tun error: {0}")]
    Tun(#[from] tun::Error),
}

#[derive(Default)]
pub struct TunnelBuilder {
    private_key: Option<StaticSecret>,
    listen_port: u16,
}

impl TunnelBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    pub fn private_key<K>(mut self, key: K) -> Result<Self, KeyParseError>
    where
        K: TryInto<PrivateKey, Error = KeyParseError>,
    {
        self.private_key = Some(key.try_into()?.into());
        Ok(self)
    }

    pub fn build(self) -> std::io::Result<Tunnel> {
        Tunnel::new(self.private_key, self.listen_port)
    }

    pub fn with_device<D>(self, device: D) -> std::io::Result<TunnelDeviceBuilder<D>>
    where
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tunnel = self.build()?;
        Ok(TunnelDeviceBuilder {
            device,
            tunnel,
            has_pi: false,
        })
    }

    #[cfg(unix)]
    pub fn attach_fd(
        self,
        raw_fd: RawFd,
    ) -> Result<TunnelDeviceBuilder<Compat<tun::AsyncDevice>>, TunnelBuilderError> {
        let tunnel = self.build()?;

        let mut config = tun::Configuration::default();
        config.raw_fd(raw_fd);

        let device = Compat::new(tun::create_as_async(&config)?);

        Ok(TunnelDeviceBuilder {
            device,
            tunnel,
            has_pi: false,
        })
    }
}

pub struct TunnelDeviceBuilder<D>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    device: D,
    tunnel: Tunnel,
    has_pi: bool,
}
impl<D> TunnelDeviceBuilder<D>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn has_packet_info(mut self, has_pi: bool) -> Self {
        self.has_pi = has_pi;
        self
    }

    pub fn build(self) -> std::io::Result<TunnelDevice<Device<D>>> {
        let device = Device::new(self.device, self.has_pi);
        Ok(TunnelDevice {
            device,
            tunnel: self.tunnel,
        })
    }

    pub fn spawn(self) -> std::io::Result<TunnelDeviceHandle> {
        self.build().map(|r| r.spawn())
    }
}

pub struct TunnelDevice<D> {
    device: D,
    tunnel: Tunnel,
}

impl<D> TunnelDevice<D>
where
    D: Stream<Item = Result<Packet, std::io::Error>>
        + Sink<Packet, Error = std::io::Error>
        + Unpin
        + Send
        + 'static,
{
    async fn run(self, token: CancellationToken) {
        let (dev_sink, dev_stream) = self.device.split();
        let (peers_sink, peers_stream) = self.tunnel.split();

        futures::select! {
            _ = token.cancelled().fuse() => {
            },
            r  = dev_stream.forward(peers_sink).fuse() => {
                println!("done dev -> peers: {r:?}");
            },
            r  = peers_stream.forward(dev_sink).fuse() => {
                println!("done peers -> dev: {r:?}");
            }
        }
    }

    pub fn spawn(self) -> TunnelDeviceHandle {
        let token: CancellationToken = CancellationToken::new();
        let thread_token = token.child_token();
        let api_channel = self.tunnel.open_api();

        let handle = tokio::spawn(async move {
            self.run(thread_token).await;
        });

        TunnelDeviceHandle {
            token,
            handle,
            api_channel,
        }
    }
}

pub struct TunnelDeviceHandle {
    token: CancellationToken,
    handle: JoinHandle<()>,
    api_channel: api::ApiChannel,
}

impl TunnelDeviceHandle {
    pub fn api(&self) -> api::ApiChannel {
        self.api_channel.clone()
    }

    pub fn cancel(&self) {
        self.token.cancel()
    }
}

impl Future for TunnelDeviceHandle {
    type Output = Result<(), JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.handle.poll_unpin(cx)
    }
}
