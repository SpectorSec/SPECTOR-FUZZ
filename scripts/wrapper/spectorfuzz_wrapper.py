#!/usr/bin/env python3
import os
import sys
import subprocess
import signal
import time
import json
import shutil
from pathlib import Path

# Path to the compiled SpectorFuzz binary
SPECTORFUZZ_BIN = "/workspace/_global/spectorfuzz/target/release/spectorfuzz"
CONVERTER_SCRIPT = "/workspace/_global/spectorfuzz/scripts/wrapper/cov_to_lcov.py"

class SpectorWrapper:
    def __init__(self):
        self.args = sys.argv[1:]
        self.workspace_dir = os.getcwd()
        self.target_contract = "CryticTester"
        self.test_mode = "assertion"
        self.replay_file = None
        self.corpus_dir = "recon"
        self.fuzzer_process = None
        self.shutdown_received = False
        
        self.parse_arguments()
        
    def parse_arguments(self):
        # Scan through the arguments passed by the extension
        i = 0
        while i < len(self.args):
            arg = self.args[i]
            if arg == "--contract" and i + 1 < len(self.args):
                self.target_contract = self.args[i+1]
                i += 2
            elif arg == "--test-mode" and i + 1 < len(self.args):
                self.test_mode = self.args[i+1]
                i += 2
            elif arg == "--replay" and i + 1 < len(self.args):
                self.replay_file = self.args[i+1]
                i += 2
            elif (arg == "--corpus-dir" or arg == "--recon-corpus-dir") and i + 1 < len(self.args):
                self.corpus_dir = self.args[i+1]
                i += 2
            else:
                i += 1

    def load_user_config(self):
        # Look for a spectorfuzz.json configuration in the workspace root
        config_path = os.path.join(self.workspace_dir, "spectorfuzz.json")
        default_config = {
            "concolic": True,
            "sha3_bypass": True,
            "detectors": "high_confidence",
            "fork_mode": False,
            "fork_block": None,
            "rpc_url": "https://eth-mainnet.g.alchemy.com/v2/ZudLM8AAn0OCfiE5JvhAL",
            "flashloan": True
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    user_cfg = json.load(f)
                    default_config.update(user_cfg)
                    print(f"[SpectorWrapper] Loaded configuration from {config_path}")
            except Exception as e:
                print(f"[SpectorWrapper] Error reading config file: {e}")
        else:
            # Create a default spectorfuzz.json so the user can edit it
            try:
                with open(config_path, "w") as f:
                    json.dump(default_config, f, indent=4)
                    print(f"[SpectorWrapper] Created default configuration at {config_path}")
            except Exception as e:
                print(f"[SpectorWrapper] Failed to write default config: {e}")
                
        return default_config

    def build_command(self, config):
        # Start building the SpectorFuzz CLI command
        cmd = [SPECTORFUZZ_BIN, "evm"]
        
        # Point to the target build folder.
        # Foundry puts compiled contracts in out/, which matches the glob target "-t 'out/*'"
        cmd += ["-t", "out/*"]
        
        # Configure detectors based on test mode
        # If property mode is selected, make sure to enable the invariant/echidna oracles
        if self.test_mode == "property":
            cmd += ["--detectors", "invariant,echidna,typed_bug"]
        else:
            cmd += ["--detectors", "typed_bug"]
            
        # Concolic & SHA3 symbolic flags
        if config.get("concolic", True):
            cmd.append("--concolic")
        if config.get("sha3_bypass", True):
            cmd.append("--sha3-bypass")
            
        # Flashloan simulation
        if config.get("flashloan", True):
            cmd.append("--flashloan")
            
        # Check if fork mode is enabled in config
        if config.get("fork_mode", False):
            cmd += ["-c", "eth"]
            if config.get("fork_block"):
                cmd += ["-b", str(config["fork_block"])]
            if config.get("rpc_url"):
                cmd += ["--onchain-url", config["rpc_url"]]
                
        # If replaying a corpus item
        if self.replay_file:
            cmd += ["-r", self.replay_file]
            
        return cmd

    def update_coverage(self):
        # Locate the generated coverage.json in work_dir
        cov_json_path = os.path.join(self.workspace_dir, "work_dir", "coverage.json")
        if not os.path.exists(cov_json_path):
            return
            
        # Generate the output LCOV path that the Recon extension watches
        timestamp = int(time.time())
        lcov_dir = os.path.join(self.workspace_dir, self.corpus_dir)
        os.makedirs(lcov_dir, exist_ok=True)
        lcov_path = os.path.join(lcov_dir, f"covered.{timestamp}.lcov")
        
        # Run our LCOV converter script
        try:
            subprocess.run(
                ["python3", CONVERTER_SCRIPT, cov_json_path, lcov_path],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            # Remove older lcov files in the folder to keep VS Code responsive
            for file in os.listdir(lcov_dir):
                if file.endswith(".lcov") and file != f"covered.{timestamp}.lcov":
                    try:
                        os.remove(os.path.join(lcov_dir, file))
                    except Exception:
                        pass
        except Exception as e:
            print(f"[SpectorWrapper] Failed to update coverage LCOV: {e}")

    def run(self):
        config = self.load_user_config()
        cmd = self.build_command(config)
        
        print(f"[SpectorWrapper] Executing SpectorFuzz: {' '.join(cmd)}")
        
        # Set up cleanup handlers
        def cleanup(signum, frame):
            self.shutdown_received = True
            if self.fuzzer_process:
                print("\n[SpectorWrapper] Stopping fuzzer process...")
                self.fuzzer_process.terminate()
                try:
                    self.fuzzer_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.fuzzer_process.kill()
            self.update_coverage()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, cleanup)
        signal.signal(signal.SIGTERM, cleanup)
        
        # Start fuzzer process
        # We pipe stdout and stderr so we can stream them directly to VS Code in real-time
        self.fuzzer_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        last_cov_update = time.time()
        
        # Read stdout line by line and stream it
        while True:
            line = self.fuzzer_process.stdout.readline()
            if not line and self.fuzzer_process.poll() is not None:
                break
            if line:
                # Print to stdout so the extension captures it
                sys.stdout.write(line)
                sys.stdout.flush()
                
            # Periodically convert coverage.json to standard LCOV (every 3 seconds)
            now = time.time()
            if now - last_cov_update > 3.0:
                self.update_coverage()
                last_cov_update = now
                
        # Final coverage update on exit
        self.update_coverage()
        print(f"\n[SpectorWrapper] Fuzzer completed with exit code: {self.fuzzer_process.returncode}")
        sys.exit(self.fuzzer_process.returncode)

if __name__ == "__main__":
    wrapper = SpectorWrapper()
    wrapper.run()
