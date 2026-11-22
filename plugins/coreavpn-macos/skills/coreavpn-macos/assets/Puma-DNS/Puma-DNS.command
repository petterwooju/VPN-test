#!/bin/bash
cd "$(dirname "$0")" || exit 1
/usr/bin/python3 -I ./session.py "$@"
result=$?
if (( result != 0 )); then
    printf '\nEnter를 누르면 종료합니다. '
    read -r
fi
exit "$result"
