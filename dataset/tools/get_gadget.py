import sys
import os

binary_folder_path = '../benchmark/benchmark_binary'

benchmark_gadget_folder_path = "../benchmark/benchmark_gadget"
if not os.path.exists(benchmark_gadget_folder_path):
    os.makedirs(benchmark_gadget_folder_path)

for i in range(len(os.listdir(binary_folder_path))):
    if 'gdb' not in os.listdir(binary_folder_path)[i]:
        binarys = os.path.join(binary_folder_path, os.listdir(binary_folder_path)[i])
        gadgets = os.path.join(benchmark_gadget_folder_path, os.listdir(binary_folder_path)[i])
        if not os.path.exists(gadgets):
            os.makedirs(gadgets)
        binarys_name = os.listdir(binarys)
        for j in range(len(binarys_name)):
            if binarys_name[j].endswith(".bin"):
                binary_path = f"{binarys}/{binarys_name[j]}"
                print(binary_path)
                size = os.path.getsize(binary_path)
                if size > 33554432:
                    os.system(f"ROPgadget --binary {binarys}/{binarys_name[j]} > {gadgets}/{binarys_name[j]}.txt")
                else:
                    os.system(f"ROPgadget --binary {binarys}/{binarys_name[j]} --depth 35 > {gadgets}/{binarys_name[j]}.txt")