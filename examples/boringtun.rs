use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
};

use async_compat::Compat;
use boringtun_async::{TunnelBuilder, WgConfig};
use clap::{Arg, Command};
use ip_network::IpNetwork;

/// Main function that runs the BoringTun VPN client.
#[tokio::main]
async fn main() {
    // Create a new command line interface using the `clap` crate
    let cmd = Command::new("vpn-service")
        .version(env!("CARGO_PKG_VERSION"))
        .args(&[
            Arg::new("config")
                .long("config")
                .required(true)
                .value_parser(clap::value_parser!(String))
                .help("Wireguard configuration file"),
            Arg::new("dev")
                .long("device")
                .value_parser(clap::value_parser!(String))
                .default_value("utun42")
                .help("Tunnel device name"),
        ]);

    // Parse the command line arguments
    let args = cmd.get_matches();
    let config_file = args.get_one::<String>("config").unwrap();
    let device_name = args.get_one::<String>("dev").unwrap();

    // Read the Wireguard configuration file
    let data = fs::read_to_string(config_file).unwrap();
    let wg_config = WgConfig::from_str(&data).unwrap();

    // Create a new tunnel configuration
    let mut config = tun::Configuration::default();

    let netmask = IpNetwork::new_truncate(
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        wg_config.interface.address.netmask(),
    )
    .unwrap();

    // Set the tunnel device name, address, netmask, and MTU and bring up the
    // device
    config
        .name(device_name)
        .address(wg_config.interface.address.network_address())
        .netmask(netmask.network_address())
        .mtu(wg_config.interface.mtu.unwrap_or(1420) as i32)
        .up();

    // Set platform-specific configuration options
    #[cfg(target_os = "linux")]
    let config = config.platform(|config| {
        config.packet_information(true);
    });

    // Configure the routing via the tunnel (Linux/MacOS only)
    #[cfg(not(target_os = "windows"))]
    let config = config.destination(wg_config.interface.address.network_address());

    // Create a tunnel device asynchronously using the provided configuration
    let dev = tun::create_as_async(config).unwrap();

    // Create a new BoringTun tunnel builder
    let tunnel = TunnelBuilder::default()
        .private_key(wg_config.interface.privatekey)
        .with_device(Compat::new(dev))
        .unwrap()
        .has_packet_info(!cfg!(target_os = "windows"))
        .spawn()
        .unwrap();

    // Add a peer to the tunnel
    tunnel
        .api()
        .add_peer(
            wg_config.peer.publickey,
            wg_config.peer.endpoint,
            wg_config.peer.allowedips,
        )
        .await
        .unwrap();

    // Wait for a Ctrl+C signal to cancel the tunnel
    tokio::signal::ctrl_c().await.unwrap();
    tunnel.cancel();

    // Wait for the tunnel to finish
    tunnel.await.unwrap();
}
