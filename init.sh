#! /bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Leave empty to let GlobalPlatformPro auto-select the sole connected reader
# (PC/SC reader enumeration for dual-interface readers can shift between
# sessions — a hardcoded "(1)"/"(2)" suffix can go stale). Set this if you
# have multiple readers connected and need to pick a specific one.
READER="${GP_READER:-}"
# GlobalPlatformPro's own default test key — passing it explicitly avoids
# its "no keys given, defaulting to ..." warning on every command.
KEY="404142434445464748494A4B4C4D4E4F"

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
  if [ ${status} -eq 0 ] || ! echo "${output}" | grep -qv "not present on card"; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET} ${desc}"
    status=0
  else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET} ${desc} (exit ${status})"
  fi
  echo
  return ${status}
}

overall_status=0

# Only pass -r when a reader was explicitly requested — an empty "-r ''"
# would fail differently than simply letting gp.jar auto-select.
READER_ARGS=()
if [ -n "${READER}" ]; then
  READER_ARGS=(-r "${READER}")
fi

run_step_delete "刪除舊 applet/package（若尚未安裝過則視為正常）" \
  java -jar "${DIR}/gp.jar" -key "${KEY}" -delete 436f6f6c57616c6c657450524f -delete 436f6f6c57616c6c6574 "${READER_ARGS[@]}" \
  || overall_status=$?

if [ "$1" == "1" ]; then
  install_desc="安裝 CAP（params c0）"
  run_step "${install_desc}" \
    java -jar "${DIR}/gp.jar" -key "${KEY}" -install "${DIR}/bin/coolbitx/javacard/coolbitx.cap" -params c0 "${READER_ARGS[@]}" -default \
    || overall_status=$?
else
  install_desc="安裝 CAP（無 params）"
  run_step "${install_desc}" \
    java -jar "${DIR}/gp.jar" -key "${KEY}" -install "${DIR}/bin/coolbitx/javacard/coolbitx.cap" "${READER_ARGS[@]}" -default \
    || overall_status=$?
fi

run_step "選取 applet 並發送測試 APDU" \
  java -jar "${DIR}/gp.jar" -key "${KEY}" -apdu 00a404000d436f6f6c57616c6c657450524f -apdu 8052000000 "${READER_ARGS[@]}" -debug \
  || overall_status=$?

echo "========================================"
if [ ${overall_status} -eq 0 ]; then
  echo -e "${COLOR_OK}✔ init.sh 執行成功${COLOR_RESET}"
else
  echo -e "${COLOR_FAIL}✘ init.sh 執行失敗，請檢查上方 [FAIL] 步驟的錯誤訊息${COLOR_RESET}"
fi

exit ${overall_status}