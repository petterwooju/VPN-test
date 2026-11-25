# Offline Puma pilot

Use when temporarily disabling FlClash would disconnect Codex. The user must have authorized temporary FlClash suspension and local UI scripting. This runner uses a compiled Swift Accessibility helper; it does not require an external-controller API, store credentials, edit profiles or rely on another model call while offline.

## Online preparation

1. Keep FlClash running. Download/install all resources and compile `scripts/offline-ui.swift` to an absolute path outside the skill directory, for example `swiftc scripts/offline-ui.swift -o /absolute/workspace/build/offline-ui`. Compilation requires the Mac's existing Swift command-line tools. Do not install new dependencies after disconnecting.
2. Inspect the VPN list through Computer Use. Match the exact Puma `.net` profile and record its zero-based switch index and the total number of VPN switches; never reuse another Mac's index. The helper checks the switch count and opens that row's details to verify both hostname fields are `puma.coreavpn.net` before execution. Confirm the selected profile is off and that the list is stable. Close details afterward. Keep System Settings on VPN and FlClash on its dashboard throughout the run. Never use historic server IPs.
3. Read FlClash states with `/absolute/workspace/build/offline-ui fl-state`. The helper must already have approved Accessibility access from its launch context. If access is missing, finish the code and checks first, then explain the specific missing permission to the user; do not silently grant access or switch FlClash off. Never automate a password prompt.
4. Run the preparation command below WITHOUT `--run`, using a new log directory. This checks both UI targets and records original DNS, route, proxy and FlClash state. It performs no network changes. The relay supports DHCP-provided IPv4 DNS and a manual `223.5.5.5` setting on the active physical IPv4 service. Recovery restores automatic DNS for DHCP and the saved address for manual DNS. If another IKEv2 tunnel already owns the probe route, preparation stops and writes the reason to `events.jsonl`. Check the active VPN before retrying. Existing port-53 listeners require separate investigation; this runner does not stop or reuse them.
5. Start the real run from the user's own Terminal. After preflight succeeds, the runner calls `sudo -v` there for administrator authorization. Sudo authorization can be scoped to its terminal, so `sudo -v` in the user's Terminal does not necessarily authorize an agent shell or detached session. The runner and relay must retain this terminal; only the recovery watchdog detaches. A subsequent `sudo -n -v` must succeed without prompting. Preparation must never collect an administrator password. If a tool blocks Terminal automation, prepare a concrete launch command and ask the user to start it directly; do not bypass the restriction through another automation mechanism. Prepare the final command, log/recovery paths and cleanup first.

### FlClash builds with an empty accessibility subtree

Some builds publish a dashboard window without its switches. First check the named window using `offline-ui fl-diagnose` and `offline-ui fl-frame`. The helper also checks the main/focused window because `AXWindows` can be empty, and filters out background core processes. If named switches remain unavailable, an explicitly authorized local UI script can use `--fl-map /absolute/private/calibration.json` on the Python runner.

Create this private map from a fresh Computer Use screenshot and the helper's current window frame: `{"width": <logical-width>, "height": <logical-height>, "tun": [<relative-x>, <relative-y>], "proxy": [<relative-x>, <relative-y>]}`. Never commit another Mac's coordinates or carry them across changed layouts. The helper requires the named FlClash window to be frontmost and match the recorded size before a click. It derives TUN state only from this verified FlClash route (`utunN` via `198.18.0.1`) or a physical Ethernet or Wi-Fi interface, and proxy state from consistent HTTP/HTTPS/SOCKS flags. Unknown routes, mixed proxy flags or a changed frame stop the action. After every click it verifies the actual network state; coordinate clicks alone never establish success. This fallback is only appropriate after the current screenshot confirms those exact controls and network baseline.

```bash
python3 /absolute/skill/scripts/offline-pilot.py \
  --ui /absolute/workspace/build/offline-ui \
  --vpn-index <live-zero-based-index> --vpn-count <live-switch-count> \
  --log-dir /absolute/workspace/runs/new-preparation
```

For the real run use a different, new log directory and append `--run`. The script always takes a fresh baseline and verifies the profile again. Keep the Mac awake, unlocked and its UI undisturbed for the short test.

## Local execution and recovery

The runner starts a detached watchdog before network changes, starts its own local-only relay, validates a public Puma IPv4 answer, turns off the saved FlClash proxy/TUN switches, and verifies routing over the saved physical interface and disabled proxy flags. It then connects only the preverified Puma profile and allows 30 seconds for its switch and `ipsecN` route. Only a verified tunnel gets 20 bound ping probes.

Success, failure, signals and the 180-second watchdog all lead to recovery: disconnect the touched Puma profile, request stop of this run's relay, verify the original DNS, and restore each saved FlClash switch independently. One failed cleanup step does not skip the others. Recovery is serialized; a failed recovery can be retried with:

```bash
python3 /absolute/skill/scripts/offline-pilot.py \
  --recover --log-dir /absolute/workspace/runs/actual-run
```

The watchdog retains the single-run lock after worker death. It terminates the worker before attempting restoration so it cannot resume connecting during cleanup. A crashed helper, changed UI, locked screen, revoked permission, machine shutdown or broken FlClash service can prevent verified UI recovery; never claim guaranteed restoration. Read `events.jsonl`, `recovered.json`, `relay-console.txt` and `ping-results.jsonl` after Codex reconnects. Manually verify route, DNS and visible FlClash/Puma state. Restored switches alone do not prove Codex is online.

If local recovery fails, disconnect only the tested Puma profile in System Settings, create `relay-state/stop` in this run's directory, verify DNS against `plan.json`, and restore the saved TUN/proxy values in FlClash. Do not kill arbitrary DNS listeners. The watchdog never changes other VPNs or invents a DNS restore address.

This helper deliberately ends a pilot disconnected from Puma and restores the original FlClash state. It does not implement persistent 100ms searches or multi-server calibration. Those modes need their own complete bounded offline payload and explicit retention/recovery behavior before FlClash is disabled.

## Replace an active VPN with FlClash after the pilot

Use `--replace-vpn INDEX NAME` only when the user requests disconnecting that active VPN and leaving it off. Verify its name and index in System Settings, and confirm the FlClash dashboard shows a stopped engine with TUN and System Proxy enabled. Add the engine start button's current position to the private calibration as an `engine` pair. Pass the dashboard's local HTTP proxy port via `--fl-proxy-port` if it differs from 7890.

Preparation verifies both VPN profiles and the local FlClash controls. The armed runner validates the DNS relay over the physical uplink before disconnecting the specified VPN. After measurement or an interruption following that disconnect attempt, recovery disconnects Puma, restores the saved DNS configuration, starts FlClash, enables TUN and System Proxy, and verifies HTTPS to the OpenAI API over the local proxy. The unauthenticated check requires no API credentials.
