#!/bin/bash
mkdir -p /dataset
cp /DynOP/dataset/benchmark/benchmark_binary/debian-10-cloud/* /dataset
python3 /experiment/run_execve.py
mv /experiment/output.jsonl  /DynOP/result/sota/ropbot/execve/debian-10-cloud.jsonl
rm /dataset/*
