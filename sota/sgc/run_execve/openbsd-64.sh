#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/openbsd-64/* /dataset
python3 /experiment/run_execve.py
mv /experiment/output.jsonl  /DynOP/result/sota/sgc/execve/openbsd-64.jsonl
rm /dataset/*
