import subprocess
import time
import os
from pwn import *

experiment_fold = "/home/angr/angrop/my-rop/benchmark_experiment"
benchmark_mem_reg_info_fold = os.path.join(experiment_fold, "benchmark_mem_reg_info_fold")

if not os.path.exists(benchmark_mem_reg_info_fold):
    os.makedirs(benchmark_mem_reg_info_fold)

vuln_fold = './binaries/x86/reallife/vuln/'

for system in os.listdir(vuln_fold):
    system_fold = os.path.join(vuln_fold, system)

    for bin in os.listdir(system_fold):
        binary = os.path.join(system_fold, bin)
        if bin != ".gdb_history" and bin.endswith(".bin"):
            if not os.path.exists(os.path.join(benchmark_mem_reg_info_fold, system)):
                os.makedirs(os.path.join(benchmark_mem_reg_info_fold, system))

            binary_fold = os.path.join(benchmark_mem_reg_info_fold, system, bin[:-4])
            print(binary)
            if not os.path.exists(binary_fold):
                os.makedirs(binary_fold)
            while(len(os.listdir(binary_fold)) == 0):
                gdbserver_cmd = [
                    "gdbserver", "127.0.0.1:1234",
                    binary,
                    f"./poc_cycli", "0"
                ]
                gdbserver_process = subprocess.Popen(
                    gdbserver_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                print(gdbserver_cmd)
                time.sleep(1)

                gdb_cmd = ["gdb", "-ex", f"set env ARG_PATH={binary_fold}", "-ex",
                        f"source ../gdb_script.py"]
                gdb_process = subprocess.Popen(
                    gdb_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )

                print(gdb_cmd)
                time.sleep(10)
                try:
                    while True:
                        gdb_exit_code = gdb_process.poll()
                        gdbserver_exit_code = gdbserver_process.poll()
                        if gdb_exit_code is not None or gdbserver_exit_code is not None:
                            break

                    time.sleep(1)

                finally:
                    if gdb_process.poll() is None:
                        gdb_process.terminate()
                        gdb_process.wait()
                    if gdbserver_process.poll() is None:
                        gdbserver_process.terminate()
                        gdbserver_process.wait()
                    time.sleep(1)
                # exit()