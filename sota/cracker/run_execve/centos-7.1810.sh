#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/centos-7.1810/* /dataset
python3 /experiment/run_execve.py
mv /experiment/output.jsonl  /DynOP/result/sota/cracker/execve/centos-7.1810.jsonl
rm /dataset/*