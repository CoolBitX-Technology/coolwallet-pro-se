#! /bin/bash
if [[ ! -z $1 ]]; then
cardIdLen=$(printf "%02x" $(echo -n "$1" | wc -m))
cardId=$(echo -n "$1" | xxd -p)
java -jar gp.jar --delete 436f6f6c57616c6c657450524f --delete 436f6f6c57616c6c6574 -r "Identiv uTrust 3700 F CL Reader 0"
java -jar gp.jar --delete 4261636b75704170706c6574 --delete 4261636b7570 -r "Identiv uTrust 3700 F CL Reader 0"
java -jar gp.jar --install ./bin/coolbitx/sio/javacard/sio.cap -r "Identiv uTrust 3700 F CL Reader 0"
java -jar gp.jar -apdu 00a404000c4261636b75704170706c6574 -apdu 80000000$cardIdLen$cardId -r "Identiv uTrust 3700 F CL Reader 0" -debug
echo "end"
else
  echo "Please enter card id"
fi