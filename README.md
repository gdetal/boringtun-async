# boringtun-async

`boringtun-async` is an implementation of the boringtun device layer in async tokio. The main objective of this project is to provide an implementation that is compatible with Windows, macOS, and Linux operating systems.

The project is a work in progress but has been successfully tested on all platforms listed above.

## Example

The repository contains a single example that demonstrates how to start a Wireguard client using a Wireguard configuration file. It creates the tunnel device but does not handle the routing part.

To start the client, run the following command:
```
$ cargo run --example boringtun -- --config wg.conf
```

On MacOS, to route all IPv4 traffic through the tunnel, except for the tunnel packets themselves to the tunnel endpoint, you can use the following configuration:
```
$ sudo route add <ENDPOINT> <LOCAL_GATEWAY>
$ sudo route change 0.0.0.0/0 <TUN_ADDRESS>
```

