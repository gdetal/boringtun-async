use async_compat::Compat;
use boringtun_async::TunnelBuilder;
use ip_network::IpNetwork;

#[tokio::main]
async fn main() {
    let mut config = tun::Configuration::default();

    config
        .name("utun42")
        .address((10, 2, 0, 2))
        .netmask((255, 255, 255, 255))
        .mtu(1440)
        .up();

    #[cfg(target_os = "linux")]
    let config = config.platform(|config| {
        config.packet_information(true);
    });

    #[cfg(not(target_os = "windows"))]
    let config = config.destination((10, 2, 0, 2));

    let dev = tun::create_as_async(&config).unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        let handle = net_route::Handle::new().unwrap();
        let route = net_route::Route::new("146.59.195.115".parse().unwrap(), 32)
            .with_gateway("10.2.0.2".parse().unwrap());
        handle.add(&route).await.unwrap();
    }

    let tunnel = TunnelBuilder::default()
        .private_key("aCyyrK5JeEPNkCs4fm92YcYnefQSvekUeJUGl1Kh5UE=")
        .unwrap()
        .with_device(Compat::new(dev))
        .unwrap()
        .has_packet_info(!cfg!(target_os = "windows"))
        .spawn()
        .unwrap();

    tunnel
        .api()
        .add_peer(
            "MK3425tJbRhEz+1xQLxlL+l6GNl52zKNwo5V0fHEwj4=",
            "195.181.167.193:51820".parse().unwrap(),
            vec![IpNetwork::from_str_truncate("0.0.0.0/0").unwrap()],
        )
        .await
        .unwrap();

    tokio::signal::ctrl_c().await.unwrap();
    tunnel.cancel();

    tunnel.await.unwrap();
}
