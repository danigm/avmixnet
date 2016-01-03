#!/bin/bash

python req.py localhost:5000 "DECRYPT 1 localhost:5000,localhost:5001 $(cat cipher.txt)"
