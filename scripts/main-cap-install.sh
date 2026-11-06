#! /bin/bash
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
# Leave empty to let GlobalPlatformPro auto-select the sole connected reader
# (PC/SC reader enumeration for dual-interface readers can shift between
# sessions — a hardcoded "(1)"/"(2)" suffix can go stale). Set this if you
# have multiple readers connected and need to pick a specific one.
READER="${GP_READER:-}"
# GlobalPlatformPro's own default test key — passing it explicitly avoids
# its "no keys given, defaulting to ..." warning on every command.
KEY="404142434445464748494A4B4C4D4E4F"
# Main goes into the SSD, as on production cards, so SecureSession uses the
# SSD's keyset 0A. Create it first with scripts/ssd-setup.sh. sio stays in
# the ISD (sio-cap-install.sh).
SSD_AID="A000000151535041"
PACKAGE_AID="436f6f6c57616c6c6574"
APPLET_AID="436f6f6c57616c6c657450524f"

COLOR_OK="\033[32m"
COLOR_FAIL="\033[31m"
COLOR_RESET="\033[0m"

# Runs one step, echoing its command output, then prints a clear
# [OK]/[FAIL] summary line based on the command's exit code.
run_step() {
  local desc="$1"
  shift
  echo "==> ${desc}"
  "$@"
  local status=$?
  if [ ${status} -eq 0 ]; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET} ${desc}"
  else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET} ${desc} (exit ${status})"
  fi
  echo
  return ${status}
}

# gp.jar exits non-zero when a -delete target AID isn't on the card yet
# (expected on a first run / already-clean card) — treat that case as OK.
run_step_delete() {
  local desc="$1"
  shift
  echo "==> ${desc}"
  local output
  output="$("$@" 2>&1)"
  local status=$?
  echo "${output}"
  if [ ${status} -eq 0 ] || echo "${output}" | grep -q "not present on card"; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET} ${desc}"
    status=0
  else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET} ${desc} (exit ${status})"
  fi
  echo
  return ${status}
}

# gp.jar's -apdu exits 0 regardless of the card's status word, so check the
# "A<< (len+2) (time) [data] SW" lines from -debug: every response must be 9000.
run_step_apdu() {
  local desc="$1"
  shift
  echo "==> ${desc}"
  local output
  output="$("$@" 2>&1)"
  local status=$?
  echo "${output}"
  local sws
  sws="$(echo "${output}" | grep '^A<<' | awk '{print toupper($NF)}')"
  if [ ${status} -eq 0 ] && [ -z "${sws}" ]; then
    status=1
  elif [ ${status} -eq 0 ] && echo "${sws}" | grep -qv '^9000$'; then
    status=1
  fi
  if [ ${status} -eq 0 ]; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET} ${desc}"
  else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET} ${desc} (exit ${status}, SW: $(echo ${sws}))"
  fi
  echo
  return ${status}
}

overall_status=0

# Check before touching the card, so a missing CAP doesn't delete the
# installed applet first. bin/ is wiped by scripts/build.sh (also run by
# run-web-server.sh), so this is a common case.
MAIN_CAP="${PROJECT_ROOT}/bin/coolbitx/javacard/coolbitx.cap"
if [ ! -f "${MAIN_CAP}" ]; then
  echo -e "${COLOR_FAIL}✘ 找不到 CAP 檔：${MAIN_CAP}${COLOR_RESET}"
  echo "  請先執行 scripts/cap-build.sh"
  exit 1
fi

# Only pass -r when a reader was explicitly requested — an empty "-r ''"
# would fail differently than simply letting gp.jar auto-select.
READER_ARGS=()
if [ -n "${READER}" ]; then
  READER_ARGS=(-r "${READER}")
fi
# Lists the card, trying again until gp.jar shows the ISD: right after a
# dropped contactless link the card answers 6982 to everything until it has
# been left alone for several seconds.
card_list() {
  local output i
  for i in 1 2 3 4; do
    [ ${i} -gt 1 ] && sleep 5
    output="$(java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -list "${READER_ARGS[@]}" 2>&1)"
    if echo "${output}" | grep -q "^ISD: "; then
      break
    fi
  done
  echo "${output}"
}

# Check the SSD before touching the card, so a card without it doesn't lose
# its main applet first.
if ! card_list | grep -qi "^DOM: ${SSD_AID}"; then
  echo -e "${COLOR_FAIL}✘ 卡片上沒有 SSD ${SSD_AID}${COLOR_RESET}"
  echo "  請先執行 scripts/ssd-setup.sh"
  exit 1
fi

# Delete applet and package in separate calls so each gets its own
# [OK]/[FAIL] result. Applet must go first.
run_step_delete "刪除舊 applet（若尚未安裝過則視為正常）" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -delete "${APPLET_AID}" "${READER_ARGS[@]}" \
  || overall_status=$?

run_step_delete "刪除舊 package（若尚未安裝過則視為正常）" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -delete "${PACKAGE_AID}" "${READER_ARGS[@]}" \
  || overall_status=$?

PARAMS_ARGS=()
install_desc="安裝 CAP 到 SSD ${SSD_AID}（無 params）"
if [ "$1" == "1" ]; then
  PARAMS_ARGS=(-params c0)
  install_desc="安裝 CAP 到 SSD ${SSD_AID}（params c0）"
fi
if ! run_step "${install_desc}" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -install "${MAIN_CAP}" "${PARAMS_ARGS[@]}" --to "${SSD_AID}" "${READER_ARGS[@]}" -default; then
  # Over contactless, creating the applet (about 1.2 s) can drop the link
  # (SCARD_E_NOT_TRANSACTED) after the package has loaded. The card rolls the
  # INSTALL back, so create the instance once more from the loaded package.
  echo "等待卡片恢復（10 秒）..."
  sleep 10
  listing="$(card_list)"
  if echo "${listing}" | grep -qi "^PKG: ${PACKAGE_AID}" && ! echo "${listing}" | grep -qi "^APP: ${APPLET_AID}"; then
    run_step "package 已載入，補建 applet" \
      java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" --package "${PACKAGE_AID}" --applet "${APPLET_AID}" \
      --create "${APPLET_AID}" "${PARAMS_ARGS[@]}" --to "${SSD_AID}" "${READER_ARGS[@]}" -default \
      || overall_status=$?
  else
    overall_status=1
  fi
fi

run_step_apdu "選取 applet 並發送測試 APDU" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -apdu "00a404000d${APPLET_AID}" -apdu 8052000000 "${READER_ARGS[@]}" -debug \
  || overall_status=$?

echo "========================================"
if [ ${overall_status} -eq 0 ]; then
  echo -e "${COLOR_OK}✔ main-cap-install.sh 執行成功${COLOR_RESET}"
else
  echo -e "${COLOR_FAIL}✘ main-cap-install.sh 執行失敗，請檢查上方 [FAIL] 步驟的錯誤訊息${COLOR_RESET}"
fi

exit ${overall_status}