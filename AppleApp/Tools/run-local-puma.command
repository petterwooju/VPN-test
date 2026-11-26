#!/bin/bash
set -euo pipefail
if [[ $# -ne 0 ]] && ! [[ $# -eq 2 && ${1:-} == --measurement && ${2:-} =~ ^(https|icmp)$ ]]; then
    printf 'Usage: %s [--measurement https|icmp]\n' "$0" >&2
    exit 2
fi
measurement="${2:-https}"
BASE="${COREAVPN_PUMA_RUNTIME:?Pass the local pilot runtime directory}"
RUNNER="$BASE/VPN-test/plugins/coreavpn-macos/skills/coreavpn-macos/scripts/offline-pilot.py"
UI="$BASE/build/offline-ui-quick"
MAP="${COREAVPN_PUMA_MAP:-$BASE/runs/20261122-101932-puma/fl-map-venus.json}"
if [[ -n "${COREAVPN_PUMA_RUN_ID:-}" ]]; then
    if ! [[ "$COREAVPN_PUMA_RUN_ID" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; then
        printf '%s\n' 'Invalid Puma test run ID.' >&2
        exit 2
    fi
    RUN="$BASE/runs/$COREAVPN_PUMA_RUN_ID-puma-pilot"
else
    RUN="$BASE/runs/$(/bin/date '+%Y%m%d-%H%M%S')-puma-pilot"
fi
printf 'Puma test (%s): VPN settings will open automatically. Keep the VPN and FlClash windows unchanged during the test.\n' "$measurement"
printf '%s\n' 'Enter your Mac administrator password ONLY at the sudo prompt below.'
printf '%s\n' "$RUN" > "$BASE/runs/latest-puma-run.txt"
printf '%s\n' 'Checking the current VPN and FlClash before requesting administrator access.'
set +e
/usr/bin/caffeinate -di /usr/bin/python3 -B "$RUNNER" --ui "$UI" --fl-map "$MAP" \
    --test-profile CoreaVPN_TEST --cycle-fl-engine --measurement "$measurement" --log-dir "$RUN" --run 2>&1 | /usr/bin/tee "$BASE/runs/latest-puma-console.txt"
result=${PIPESTATUS[0]}
set -e
printf 'Run log: %s\n' "$RUN"
exit "$result"
