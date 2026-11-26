# Offline Puma pilot

Use when temporarily disabling FlClash would disconnect Codex. The user must have authorized temporary FlClash suspension and local UI scripting. This runner uses a compiled Swift Accessibility helper. On this Mac it temporarily changes the server address and remote ID of `CoreaVPN_TEST` and restores both values during cleanup.

## Online preparation

1. Keep FlClash running. Download/install all resources and compile `scripts/offline-ui.swift` to an absolute path outside the skill directory, for example `swiftc scripts/offline-ui.swift -o /absolute/workspace/build/offline-ui`. Compilation requires the Mac's existing Swift command-line tools. Do not install new dependencies after disconnecting.
2. Keep FlClash on its dashboard. Preparation locates the disconnected `CoreaVPN_TEST` entry in macOS VPN settings by exact name and snapshots its endpoints. The named commands discover the current row and count.
3. Read FlClash states with `/absolute/workspace/build/offline-ui fl-state`. The helper must already have approved Accessibility access from its launch context. If access is missing, finish the code and checks first, then explain the specific missing permission to the user; do not silently grant access or switch FlClash off. Never automate a password prompt.
4. Run the preparation command below WITHOUT `--run`, using a new log directory. This checks both UI targets and records original DNS, route, proxy and FlClash state. It performs no network changes. The relay supports DHCP-provided IPv4 DNS and a manual `223.5.5.5` setting on the active physical IPv4 service. Recovery restores automatic DNS for DHCP and the saved address for manual DNS. If another IKEv2 tunnel already owns the probe route, preparation stops and writes the reason to `events.jsonl`. Check the active VPN before retrying. Existing port-53 listeners require separate investigation; this runner does not stop or reuse them.
5. Start the real run from the user's own Terminal. After preflight succeeds, the runner calls `sudo -v` there for administrator authorization. Sudo authorization can be scoped to its terminal, so `sudo -v` in the user's Terminal does not necessarily authorize an agent shell or detached session. The runner and relay must retain this terminal; only the recovery watchdog detaches. A subsequent `sudo -n -v` must succeed without prompting. Preparation must never collect an administrator password. If a tool blocks Terminal automation, prepare a concrete launch command and ask the user to start it directly; do not bypass the restriction through another automation mechanism. Prepare the final command, log/recovery paths and cleanup first.

### FlClash builds with an empty accessibility subtree

Some builds publish a dashboard window without its switches. First check the named window using `offline-ui fl-diagnose` and `offline-ui fl-frame`. The helper also checks the main/focused window because `AXWindows` can be empty, and filters out background core processes. If named switches remain unavailable, an explicitly authorized local UI script can use `--fl-map /absolute/private/calibration.json` on the Python runner.

Create this private map from a fresh Computer Use screenshot and the helper's current window frame: `{"width": <logical-width>, "height": <logical-height>, "tun": [<relative-x>, <relative-y>], "proxy": [<relative-x>, <relative-y>]}`. Never commit another Mac's coordinates or carry them across changed layouts. The helper requires the named FlClash window to be frontmost and match the recorded size before a click. It derives TUN state only from this verified FlClash route (`utunN` via `198.18.0.1`) or a physical Ethernet or Wi-Fi interface, and proxy state from consistent HTTP/HTTPS/SOCKS flags. Unknown routes, mixed proxy flags or a changed frame stop the action. After every click it verifies the actual network state; coordinate clicks alone never establish success. This fallback is only appropriate after the current screenshot confirms those exact controls and network baseline.

```bash
python3 /absolute/skill/scripts/offline-pilot.py \
  --ui /absolute/workspace/build/offline-ui \
  --test-profile CoreaVPN_TEST --cycle-fl-engine --fl-map /absolute/private/calibration.json \
  --log-dir /absolute/workspace/runs/new-preparation
```

For the real run use a different, new log directory and append `--run`. The script always takes a fresh baseline and verifies the profile again. Keep the Mac awake, unlocked and its UI undisturbed for the short test.

## Local execution and recovery

The runner starts a detached watchdog before network changes, starts its own local-only relay, validates a public Puma IPv4 answer, turns off the saved FlClash proxy/TUN switches, and verifies routing over the saved physical interface and disabled proxy flags. It retargets the verified `CoreaVPN_TEST` profile to Puma and allows 30 seconds for its switch and `ipsecN` route. With `--measurement icmp`, it checks the tunnel route to `168.126.63.1` and sends 20 pings. With `--measurement https` (the default), it resolves `speed.cloudflare.com` and checks the route to the chosen public IPv4 address. The probe binds its TLS sockets to that tunnel and measures 20 small HTTPS requests at idle, download and upload rates, and request delay during each transfer phase. The transfer measurement is bounded in time and bytes.

The runner attempts recovery on completion, failure, a stop request, or the 225-second watchdog deadline. Recovery disconnects `CoreaVPN_TEST`, restores its original endpoints, stops this run's relay, verifies the original DNS, and restores the saved FlClash switches. The runner records its observation of the original DNS before restarting FlClash and checks that DNS no longer points at the relay afterward. Each recovery step runs independently. Retry failed recovery with the following command.

```bash
python3 /absolute/skill/scripts/offline-pilot.py \
  --recover --log-dir /absolute/workspace/runs/actual-run
```

The watchdog retains the single-run lock after worker death and terminates the worker before restoration. A crashed helper, changed UI, locked screen, revoked permission, machine shutdown, or broken FlClash service can prevent verified recovery. Read `events.jsonl`, `recovered.json`, `relay-console.txt` and the selected method’s result file after Codex reconnects. HTTPS writes `https-results.jsonl` and ICMP writes `ping-results.jsonl`. Verify the route, DNS, visible FlClash and Puma state, and internet access.

If local recovery fails, disconnect `CoreaVPN_TEST` in System Settings, restore the endpoints recorded in `plan.json`, create `relay-state/stop` in this run's directory, verify DNS against `plan.json`, and restore the saved TUN/proxy values in FlClash. Do not kill arbitrary DNS listeners. The watchdog never changes other VPNs or invents a DNS restore address.

The runner ends the test disconnected and restores the original FlClash state. A batch measures one round. A multi-round calibration or a search that retains the best connection requires separate handling.

## Verify FlClash engine restart from a running baseline

Use `--cycle-fl-engine` with a current dashboard calibration containing `engine`, `tun` and `proxy`. The engine, TUN and system proxy must all be on at preflight. The runner stops the engine with the saved switches in place. It requires the local proxy listener, system proxy flags and TUN route to clear. It then saves the physical service's DNS and starts the temporary relay, so shutting down FlClash cannot overwrite the relay's settings. Recovery restarts the engine, restores the switches and checks the macOS HTTP, HTTPS and SOCKS proxy endpoints for 30 seconds. If the flags clear, it enables the proxy again and restarts the observation period. It also tests the OpenAI API through the proxy. Read `flclash-engine-stopped`, `start-flclash-engine`, and `system-proxy-stable` in the run's event log to verify the cycle.

## Test all servers through the dedicated profile

Use `--test-profile CoreaVPN_TEST --batch /absolute/skill/assets/servers.json --cycle-fl-engine`. The bundled catalog contains the 23 hostnames in provider order. Both local all-server launchers use this catalog. The runner binds every host to the same named profile and saves its original endpoints for recovery.

The runner tests one tunnel at a time and records each DNS, connection, or measurement failure under that server's hostname. Each tunnel must disconnect and return to the physical route before the next connection. If disconnect verification fails, the batch stops and the watchdog retries recovery for the recorded active profile. The watchdog limit is 225 seconds plus 140 seconds per candidate. Review the event log and the selected method’s result file together to account for every server.
