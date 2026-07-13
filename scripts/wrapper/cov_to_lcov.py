import os
import json
import time
import sys

def offset_to_line(file_content, offset):
    return file_content[:offset].count('\n') + 1

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 cov_to_lcov.py <coverage_json_path> <output_lcov_path>")
        sys.exit(1)
        
    cov_path = sys.argv[1]
    out_path = sys.argv[2]
    
    if not os.path.exists(cov_path):
        print(f"Coverage file not found: {cov_path}")
        sys.exit(0)
        
    try:
        with open(cov_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to parse coverage JSON: {e}")
        sys.exit(1)
        
    # We will map each file path to a set of covered lines
    file_coverage = {}
    
    # Cache file contents to avoid reading them repeatedly
    file_cache = {}
    
    # Parse the coverage dictionary
    # format: { "coverage": { "ContractName": { "covered_code": [ { "file": "src/X.sol", "offset": 12, ... } ] } } }
    coverage_dict = data.get("coverage", {})
    for contract_name, cov_res in coverage_dict.items():
        covered_code = cov_res.get("covered_code", [])
        for item in covered_code:
            if not item:
                continue
            file_name = item.get("file")
            offset = item.get("offset")
            if not file_name or offset is None:
                continue
                
            # Resolve absolute path
            abs_path = os.path.abspath(file_name)
            if not os.path.exists(abs_path):
                continue
                
            if abs_path not in file_cache:
                try:
                    with open(abs_path, 'r', errors='ignore') as f:
                        file_cache[abs_path] = f.read()
                except Exception:
                    continue
                    
            content = file_cache[abs_path]
            line_num = offset_to_line(content, offset)
            
            if abs_path not in file_coverage:
                file_coverage[abs_path] = set()
            file_coverage[abs_path].add(line_num)
            
    # Write the LCOV format
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    try:
        with open(out_path, 'w') as f:
            for abs_path, lines in file_coverage.items():
                f.write("TN:\n")
                f.write(f"SF:{abs_path}\n")
                for line in sorted(lines):
                    f.write(f"DA:{line},1\n")
                f.write("end_of_record\n")
        print(f"Successfully generated LCOV coverage report: {out_path}")
    except Exception as e:
        print(f"Failed to write LCOV file: {e}")

if __name__ == "__main__":
    main()
