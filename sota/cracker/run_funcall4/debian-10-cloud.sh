#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/debian-10-cloud/* /dataset
python3 /experiment/run_funcall4.py
mv /experiment/output.jsonl  /DynOP/result/sota/cracker/funcall4/debian-10-cloud.jsonl
rm /dataset/*