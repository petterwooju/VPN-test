# Offline Puma pilot

Use when temporarily disabling FlClash would disconnect Codex. The user must have authorized temporary FlClash suspension and local UI scripting. This runner uses a compiled Swift Accessibility helper; it does not require an external-controller API, store credentials, edit profiles or rely on another model call while offline.

## Online preparation

1. Keep FlClash running. Download/install all resources and compile `scripts/offline-ui.swift` to an absolute path outside the skill directory, for example `swiftc scripts/offline-ui.swift -o /absolute/workspace/build/offline-ui`. Compilation requires the Mac's existing Swift command-line tools. Do not install new dependencies after disconnecting.
2. Inspect the VPN list through Computer Use. Match the exact Puma `.net` profile and record its zero-based switch index and the total number of VPN switches; never reuse another Mac's index. The helper checks the switch count and opens that row's details to verify both hostname fields are `puma.coreavpn.net` before execution. Confirm the selected profile is off and that the list is stable. Close details afterward. Keep System Settings on VPN and FlClash on its dashboard throughout the run. No coordinate clicks or historic server IPs are used.
3. Read FlClash states with `/absolute/workspace/build/offline-ui fl-state`. The helper must already have approved Accessibility access from its launch context. If access is missing, finish the code and checks first, then explain the specific missing permission to the user; do not silently grant access or switch FlClash off. Never automate a password prompt.
4. Run the preparation command below WITHOUT `--run`, using a new log directory. This checks both UI targets and records original DNS, route, proxy and FlClash state. It performs no network changes. The bundled relay requires an existing manual `223.5.5.5` baseline and Wi-Fi on `en0`; other Macs need a compatible relay rather than baseline changes. Existing port-53 listeners require separate investigation; this runner does not stop or reuse them.
5. Before a real run, obtain administrator authorization in the user's own Terminal with `sudo -v`. A subsequent `sudo -n -v` must succeed without prompting. Preparation must never collect an administrator password. Launch the real run from an independent local process (prefer Terminal or a detached process with a local output file) so losing the Codex connection cannot cancel it. Prepare the final command, log/recovery paths and cleanup first.

```bash
python3 /absolute/skill/scripts/offline-pilot.py \
  --ui /absolute/workspace/build/offline-ui \
  --vpn-index <live-zero-based-index> --vpn-count <live-switch-count> \
  --log-dir /absolute/workspace/runs/new-preparation
```

For the real run use a different, new log directory and append `--run`. The script always takes a fresh baseline and verifies the profile again. Keep the Mac awake, unlocked and its UI undisturbed for the short test.

## Local execution and recovery

The runner starts a detached watchdog before network changes, starts its own local-only relay, validates a public Puma IPv4 answer, turns off the saved FlClash proxy/TUN switches, and verifies physical `en0` routing and disabled proxy flags. It then connects only the preverified Puma profile and allows 30 seconds for its switch and `ipsecN` route. Only a verified tunnel gets 20 bound ping probes.

Success, failure, signals and the 180-second watchdog all lead to recovery: disconnect the touched Puma profile, request stop of this run's relay, verify the original DNS, and restore each saved FlClash switch independently. One failed cleanup step does not skip the others. Recovery is serialized; a failed recovery can be retried with:

```bash
python3 /absolute/skill/scripts/offline-pilot.py \
  --recover --log-dir /absolute/workspace/runs/actual-run
```

The watchdog retains the single-run lock after worker death. It terminates the worker before attempting restoration so it cannot resume connecting during cleanup. A crashed helper, changed UI, locked screen, revoked permission, machine shutdown or broken FlClash service can prevent verified UI recovery; never claim guaranteed restoration. Read `events.jsonl`, `recovered.json`, `relay-console.txt` and `ping-results.jsonl` after Codex reconnects. Manually verify route, DNS and visible FlClash/Puma state. Restored switches alone do not prove Codex is online.

If local recovery fails, disconnect only the tested Puma profile in System Settings, create `relay-state/stop` in this run's directory, verify DNS against `plan.json`, and restore the saved TUN/proxy values in FlClash. Do not kill arbitrary DNS listeners. The watchdog never changes other VPNs or invents a DNS restore address.

This helper deliberately ends a pilot disconnected from Puma and restores the original FlClash state. It does not implement persistent 100ms searches or multi-server calibration. Those modes need their own complete bounded offline payload and explicit retention/recovery behavior before FlClash is disabled.
