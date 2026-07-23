#! /bin/bash
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
# Leave empty to let GlobalPlatformPro auto-select the sole connected reader
# (PC/SC reader enumeration can shift between sessions). Set this if you
# have multiple readers connected and need to pick a specific one.
READER="${GP_READER:-}"
# GlobalPlatformPro's own default test key — passing it explicitly avoids
# its "no keys given, defaulting to ..." warning on every command.
KEY="404142434445464748494A4B4C4D4E4F"

# Only pass -r when a reader was explicitly requested — an empty "-r ''"
# would fail differently than simply letting gp.jar auto-select.
READER_ARGS=()
if [ -n "${READER}" ]; then
  READER_ARGS=(-r "${READER}")
fi

if [[ ! -z $1 ]]; then
cardIdLen=$(printf "%02x" $(echo -n "$1" | wc -m))
cardId=$(echo -n "$1" | xxd -p)
java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" --delete 436f6f6c57616c6c657450524f --delete 436f6f6c57616c6c6574 "${READER_ARGS[@]}"
java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" --delete 4261636b75704170706c6574 --delete 4261636b7570 "${READER_ARGS[@]}"
java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" --install "${PROJECT_ROOT}/bin/coolbitx/sio/javacard/sio.cap" "${READER_ARGS[@]}"
java -jar "${PROJECT_ROOT}/gp.jar" -key "${KEY}" -apdu 00a404000c4261636b75704170706c6574 -apdu 80000000$cardIdLen$cardId "${READER_ARGS[@]}" -debug
echo "end"
else
  echo "Please enter card id"
fi