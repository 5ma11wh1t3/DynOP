#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/gcc_fzero/* /dataset
python3 /experiment/run_execve.py
mv /experiment/output.jsonl  /DynOP/result/sota/sgc/execve/gcc_fzero.jsonl
rm /dataset/*
