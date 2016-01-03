#!/bin/bash

cd ../
python avmix.py 5000 &
PID1=$!
python avmix.py 5001 &
PID2=$!

sleep 2

cd tests

echo "Generating key"
./test-genkey.sh | tee pubkey.txt
echo ""

echo "encrypting msgs [2, 3, 6, 4]"
python test-encrypt.py $(cat pubkey.txt) | tee cipher.txt
echo ""

echo "decrypting msgs"
./test-decrypt.sh | tee clears.txt

kill -15 $PID1
kill -15 $PID2
