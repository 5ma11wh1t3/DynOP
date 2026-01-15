#!/bin/bash

CVE_FOLDER_PATH="../real-linux-software/real_binary"

for cve_dir in "$CVE_FOLDER_PATH"/*; do
    if [ -d "$cve_dir" ]; then
        cve_name=$(basename "$cve_dir")

        cve_gadget_dir="$CVE_FOLDER_PATH/$cve_name"
        if [ ! -d "$cve_gadget_dir" ]; then
            mkdir -p "$cve_gadget_dir"
        fi
        
        echo "Software: $cve_name"
        
        for file in "$cve_dir"/*; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                
                if [[ ! "$filename" =~ \.(txt|json)$ ]]; then
                    echo "  Extracting gadget: $filename"
                    ROPgadget --binary "$file" > "$cve_gadget_dir/${filename}.txt"
                fi
            fi
        done
    fi
done

echo "Completed. Results saved to: $CVE_FOLDER_PATH"
