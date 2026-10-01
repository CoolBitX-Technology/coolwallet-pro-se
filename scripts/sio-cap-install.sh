#! /bin/bash
# Usage: sio-cap-install.sh <card id>
#
# NOTE: deleting BackupApplet wipes the card id and genuine key stored on the
# card, so only run this on a card you intend to re-provision.
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
# Leave empty to let GlobalPlatformPro auto-select the sole connected reader
# (PC/SC reader enumeration can shift between sessions). Set this if you
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

if [ -z "$1" ]; then
  echo "Please enter card id"
  echo "Usage: $0 <card id>"
  exit 1
fi

# Check before touching the card: the deletes below would otherwise wipe
# BackupApplet and then fail to install. bin/ is wiped by scripts/build.sh
# (also run by run-web-server.sh), so a missing CAP is a common case.
SIO_CAP="${PROJECT_ROOT}/bin/coolbitx/sio/javacard/sio.cap"
if [ ! -f "${SIO_CAP}" ]; then
  echo -e "${COLOR_FAIL}✘ 找不到 CAP 檔：${SIO_CAP}${COLOR_RESET}"
  echo "  請先執行 scripts/cap-build.sh"
  exit 1
fi

# Only pass -r when a reader was explicitly requested — an empty "-r ''"
# would fail differently than simply letting gp.jar auto-select.
READER_ARGS=()
if [ -n "${READER}" ]; then
  READER_ARGS=(-r "${READER}")
fi

# Lc is the byte length (not character count) of the raw id, i.e. half the
# length of its hex encoding.
cardIdLen=$(printf "%02x" "$(printf '%s' "$1" | wc -c)")
cardId=$(printf '%s' "$1" | xxd -p | tr -d '\n')

overall_status=0

# Main applet/package must be removed first since it depends on the sio
# package. Each AID is deleted in its own call so each gets its own
# [OK]/[FAIL] result; applets go before their packages.
run_step_delete "刪除 main applet（若尚未安裝過則視為正常）" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -delete 436f6f6c57616c6c657450524f "${READER_ARGS[@]}" \
  || overall_status=$?

run_step_delete "刪除 main package（若尚未安裝過則視為正常）" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -delete 436f6f6c57616c6c6574 "${READER_ARGS[@]}" \
  || overall_status=$?

# If main is still on the card, the sio package can't be deleted or
# reinstalled — stop here rather than wipe BackupApplet's card id and
# genuine key with no way to restore them.
if [ ${overall_status} -ne 0 ]; then
  echo "========================================"
  echo -e "${COLOR_FAIL}✘ main applet/package 刪除失敗，已中止（未動到 BackupApplet）${COLOR_RESET}"
  exit ${overall_status}
fi

run_step_delete "刪除 sio applet（若尚未安裝過則視為正常）" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -delete 4261636b75704170706c6574 "${READER_ARGS[@]}" \
  || overall_status=$?

run_step_delete "刪除 sio package（若尚未安裝過則視為正常）" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -delete 4261636b7570 "${READER_ARGS[@]}" \
  || overall_status=$?

if run_step "安裝 sio CAP" \
  java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -install "${SIO_CAP}" "${READER_ARGS[@]}"; then
  run_step_apdu "選取 BackupApplet 並設定 card id（$1）" \
    java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -apdu 00a404000c4261636b75704170706c6574 -apdu "80000000${cardIdLen}${cardId}" "${READER_ARGS[@]}" -debug \
    || overall_status=$?
else
  overall_status=$?
  echo -e "${COLOR_FAIL}略過設定 card id（sio CAP 安裝失敗）${COLOR_RESET}"
  echo
fi

echo "========================================"
if [ ${overall_status} -eq 0 ]; then
  echo -e "${COLOR_OK}✔ sio-cap-install.sh 執行成功${COLOR_RESET}"
else
  echo -e "${COLOR_FAIL}✘ sio-cap-install.sh 執行失敗，請檢查上方 [FAIL] 步驟的錯誤訊息${COLOR_RESET}"
fi

exit ${overall_status}
