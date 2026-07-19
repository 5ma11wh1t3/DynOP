#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/openbsd-64/* /dataset
python3 /experiment/run_funcall4.py
mv /experiment/output.jsonl  /DynOP/result/sota/cracker/funcall4/openbsd-64.jsonl
rm /dataset/*