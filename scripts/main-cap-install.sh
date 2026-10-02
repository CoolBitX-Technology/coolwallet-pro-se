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

# Delete applet and package in separate calls so each gets its own
# [OK]/[FAIL] result. Applet must go first.
run_step_delete "刪除舊 applet（若尚未安裝過則視為正常）" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -delete 436f6f6c57616c6c657450524f "${READER_ARGS[@]}" \
  || overall_status=$?

run_step_delete "刪除舊 package（若尚未安裝過則視為正常）" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -delete 436f6f6c57616c6c6574 "${READER_ARGS[@]}" \
  || overall_status=$?

if [ "$1" == "1" ]; then
  install_desc="安裝 CAP（params c0）"
  run_step "${install_desc}" \
    java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -install "${MAIN_CAP}" -params c0 "${READER_ARGS[@]}" -default \
    || overall_status=$?
else
  install_desc="安裝 CAP（無 params）"
  run_step "${install_desc}" \
    java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -install "${MAIN_CAP}" "${READER_ARGS[@]}" -default \
    || overall_status=$?
fi

run_step_apdu "選取 applet 並發送測試 APDU" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -apdu 00a404000d436f6f6c57616c6c657450524f -apdu 8052000000 "${READER_ARGS[@]}" -debug \
  || overall_status=$?

echo "========================================"
if [ ${overall_status} -eq 0 ]; then
  echo -e "${COLOR_OK}✔ main-cap-install.sh 執行成功${COLOR_RESET}"
else
  echo -e "${COLOR_FAIL}✘ main-cap-install.sh 執行失敗，請檢查上方 [FAIL] 步驟的錯誤訊息${COLOR_RESET}"
fi

exit ${overall_status}