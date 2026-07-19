#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/gcc_fzero/* /dataset
python3 /experiment/run_funcall4.py
mv /experiment/output.jsonl  /DynOP/result/sota/cracker/funcall4/gcc_fzero.jsonl
rm /dataset/*