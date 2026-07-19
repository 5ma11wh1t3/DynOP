#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/openbsd-62/* /dataset
python3 /experiment/run_funcall4.py
mv /experiment/output.jsonl  /DynOP/result/sota/cracker/funcall4/openbsd-62.jsonl
rm /dataset/*