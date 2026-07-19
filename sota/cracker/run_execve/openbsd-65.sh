#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/openbsd-65/* /dataset
python3 /experiment/run_execve.py
mv /experiment/output.jsonl  /DynOP/result/sota/cracker/execve/openbsd-65.jsonl
rm /dataset/*