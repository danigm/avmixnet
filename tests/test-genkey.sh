#!/bin/bash

rm -rf /tmp/avmix/

python req.py localhost:5000 "GEN_KEY 1 localhost:5000,localhost:5001"
