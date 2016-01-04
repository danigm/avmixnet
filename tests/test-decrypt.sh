#!/bin/bash

python req.py localhost:5000 "SHUFFLE 1 localhost:5000,localhost:5001 $(cat pubkey.txt) $(cat cipher.txt)" > shuffled.txt
python req.py localhost:5000 "DECRYPT 1 localhost:5000,localhost:5001 $(cat shuffled.txt)"
