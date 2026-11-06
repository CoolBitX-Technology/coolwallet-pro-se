#!/bin/bash
# Create the supplementary security domain (SSD) on a test card and give it
# its own SCP02 keyset, as production perso does for Pro (persoJcop4):
#   install -s -e -q C90145 A0000001515350 A000000151535041
#   put-keyset 10
# Run it before main-cap-install.sh, which installs main into this SSD so
# Pro's secure channel (SecureSession) uses its keyset. sio stays in the ISD.
# Test cards only: production perso sets per-card keys derived by the KMS.
#
# Usage: ssd-setup.sh
#   Prints the card serial first; a wrong card fails ISD authentication and
#   stops there.
#
# Environment:
#   SSD_KEY    key for the SSD keyset (ENC = MAC = DEK), hex, default: the
#              test SSD key 5051...5F, the same as cool-seed-se's test cards
#              (kept distinct from the ISD key, so a passing check proves
#              the SSD key is in use). gp.jar writes 3DES keys, as the card
#              runs SCP02.
#   GP_KEY     ISD key, default: GlobalPlatformPro's default test key
#   GP_READER  reader to use when several are connected

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISD_KEY="${GP_KEY:-404142434445464748494A4B4C4D4E4F}"
SSD_KEY="${SSD_KEY:-505152535455565758595A5B5C5D5E5F}"
SSD_PACKAGE_AID="A0000001515350"
SSD_AID="A000000151535041"
SSD_KEY_VERSION=10

COLOR_OK="\033[32m"
COLOR_FAIL="\033[31m"
COLOR_RESET="\033[0m"

fail() {
  echo -e "${COLOR_FAIL}✘ $1${COLOR_RESET}"
  exit 1
}

GP=(java -jar "$PROJECT_ROOT/gp.jar")
if [ -n "${GP_READER:-}" ]; then
  GP+=(-r "$GP_READER")
fi

# Read-only, so the log shows which card this ran on
serial="$("${GP[@]}" -info 2>&1 | awk '/ICSerialNumber=/ {sub(/.*=/, ""); print; exit}')"
echo "卡片序號：${serial:-讀不到}"
echo

# Authenticate to the ISD first. A wrong card or wrong GP_KEY fails here;
# gp.jar stops after INITIALIZE UPDATE, before EXTERNAL AUTHENTICATE, so the
# card counts no failed attempt.
echo "==> ISD 驗證"
isd_list="$("${GP[@]}" -key "$ISD_KEY" -list 2>&1)"
if ! echo "$isd_list" | grep -q "^ISD: "; then
  echo "$isd_list" | grep -E 'Failed|cryptogram|Received|Expected|rror'
  fail "ISD 驗證失敗：可能放錯卡，或 GP_KEY 不是這張卡的 ISD key"
fi
echo -e "${COLOR_OK}[OK]${COLOR_RESET} ISD"
echo

# Lists the card through the SSD with the SSD keyset. gp.jar's exit code
# isn't reliable, so success is seeing the SSD in its own listing. With a
# wrong key gp.jar stops after INITIALIZE UPDATE, before EXTERNAL
# AUTHENTICATE, so the card counts no failed attempt.
ssd_key_works() {
  "${GP[@]}" -c "$SSD_AID" -key "$SSD_KEY" --key-ver "$SSD_KEY_VERSION" -list 2>&1 \
    | grep -q "^DOM: $SSD_AID"
}

ssd_created=0
echo "==> 建立 SSD $SSD_AID"
if echo "$isd_list" | grep -q "^DOM: $SSD_AID"; then
  echo "SSD 已存在，略過"
else
  ssd_created=1
  # INSTALL [for install and make selectable], same as production perso:
  #   privileges A0 = Security Domain + Delegated Management
  #   install params C9 01 45 (accept extradition)
  install_apdu="80E60C0021"
  install_apdu+="07${SSD_PACKAGE_AID}08${SSD_AID}08${SSD_AID}"
  install_apdu+="01A0"
  install_apdu+="03C90145"
  install_apdu+="00"
  output="$("${GP[@]}" -key "$ISD_KEY" -s "$install_apdu" -d 2>&1)"
  echo "$output" | grep -E '^A(>>|<<)'
  # Status word of the response right after the INSTALL command itself
  # (sent as 84E60C00 with a C-MAC), not of the handshake before it
  install_sw="$(echo "$output" | awk '/^A>> .*84E60C00/ {found = 1; next} found && /^A<< / {print $NF; exit}')"
  [ "$install_sw" == "9000" ] || fail "建立 SSD 失敗（SW=${install_sw:-無回應}）"
fi
echo -e "${COLOR_OK}[OK]${COLOR_RESET} SSD"
echo

echo "==> 寫入 SSD keyset（key version ${SSD_KEY_VERSION}）"
if [ $ssd_created -eq 1 ]; then
  # A new SSD has no keys of its own and answers with the ISD keyset, as
  # production perso relies on
  output="$("${GP[@]}" -c "$SSD_AID" -key "$ISD_KEY" --lock "$SSD_KEY" --new-keyver "$SSD_KEY_VERSION" 2>&1)"
  echo "$output"
  echo "$output" | grep -q "locked with" || fail "寫入 SSD keyset 失敗"
elif ssd_key_works; then
  echo "SSD 已有這組 keyset，略過"
else
  # Never overwrite an existing SSD's keys on our own: they may belong to
  # another flow
  fail "SSD 已存在，但 SSD_KEY 驗證失敗。請確認 SSD_KEY，或刪除 SSD 後重跑"
fi
echo -e "${COLOR_OK}[OK]${COLOR_RESET} SSD keyset"
echo

echo "==> 用 SSD key 驗證"
ssd_key_works || fail "SSD key 驗證失敗"
echo -e "${COLOR_OK}✔ ssd-setup.sh 執行成功${COLOR_RESET}"
