# macOS proxy-group egress check

`group-egress.py` opens one SOCKS5 connection to `api.ipify.org:443`. It checks the live mihomo controller entry for this socket's source port and destination, verifies the requested group and Shadowsocks or AnyTLS leaf, and reads a public exit address over certificate-validated HTTPS. The report shows group, protocol and success. Add `--show-ip` to display the address locally.

## Isolated check with FlClash running

Supply a trusted macOS mihomo binary and an exported runtime profile with inline nodes. The Mac needs Python 3, system Ruby with Psych, and a connected physical interface. The check starts a separate mihomo process with loopback SOCKS and control ports, TUN and DNS listeners disabled. A private FIFO supplies just the selected proxy settings and a single test rule. The process and its private temporary directory are removed at exit.

```sh
python3 AppleApp/ProxyPrototype/group-egress.py --protocol ss isolated \
  --core /path/to/mihomo --interface en6 \
  --profile "$HOME/Library/Application Support/com.follow.clash/config.yaml"
```

Use `--protocol anytls` for the AnyTLS check. `--group 'Name'` before `isolated` selects a group. The default follows the profile's final MATCH rule. The check takes the first matching inline member reachable through that group, or the specific member named by `--node 'Name'`. It creates an isolated one-member group for the test. The result proves transport through that member. Selection, failover behavior and routing rules in the user's running FlClash are independent of the isolated check. Provider-only subscriptions and chained nodes require an inline/dedicated test member.

## Observe an existing group

With a loopback controller already available and a rule routing the observer to the desired group, use:

```sh
python3 AppleApp/ProxyPrototype/group-egress.py --protocol ss --group 'Name' existing \
  --socks-port 7890 --controller-port 9090
```

Set `MIHOMO_READ_TOKEN` locally if the controller requires a token. The tool only makes local HTTP GET requests to the controller, and sends no configuration or credentials to the IP observer. SOCKS connections requiring local password authentication are unsupported. The app does not enable a controller or modify FlClash settings.

On November 25, 2026 both isolated modes passed on the Beijing Mac's en6 interface and original MATCH group with official mihomo v1.19.34. The existing-mode controller was disabled in the running FlClash configuration. The isolated tool preserves the supplied proxy's upstream TLS settings. The sampled AnyTLS profile disabled upstream certificate verification; its HTTPS observer was independently authenticated.

## Route Lab on-device selection

Import the original FlClash YAML on each device in the Route Lab proxy screen. Select a group and an inline Shadowsocks or AnyTLS member, then save to the device Keychain. The extension reads the selected item through a persistent reference. Only selected group and member labels are displayed. A rule targeting that group uses the saved member.

The embedded transport supports AEAD Shadowsocks, simple-obfs TLS/HTTP, UDP-over-TCP (versions 1 and 2), and AnyTLS with certificate validation and UDP-over-TCP. For an AnyTLS source that disables verification, enter a trusted certificate server name for system CA validation, or a known SHA-256 leaf certificate fingerprint from the provider. A pinned certificate must also be valid for the requested server name and time. Unsupported options are reported at selection.

The connected test paths cover authenticated encryption, TCP, UDP datagrams and return packets. The app's single-tunnel three-way routing and iPhone network transitions require separate hardware acceptance.

[Mihomo releases](https://github.com/MetaCubeX/mihomo/releases) · [Controller API](https://wiki.metacubex.one/api/) · [IP observer](https://www.ipify.org/)

The embedded Go leaf was also tested with a member from the same Beijing profile on the physical en6 uplink. System DNS returned a synthetic FlClash address for its proxy host. Resolving that host through the scoped TLS DNS path before dialing produced a real Shadowsocks HTTPS exit and a UDP-over-TCP DNS reply. A real AnyTLS member failed the strict system certificate check with its original SNI. A local AnyTLS fixture separately verifies successful pinned TLS and rejects a mismatched pin.
