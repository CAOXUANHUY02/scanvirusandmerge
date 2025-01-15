import hashlib
import json
import os
import subprocess
from typing import Dict, Union

from dotenv import load_dotenv

load_dotenv()


class VirusTotalScanner:
    def __init__(self, vt_exec_path: str = "vt.exe"):
        print(f"Initializing VirusTotalScanner with exec path: {vt_exec_path}")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.vt_exec_path = os.path.join(current_dir, vt_exec_path)
        self.api_key = os.getenv('VT_API_KEY')
        print(f"Full VT executable path: {self.vt_exec_path}")

        if not os.path.exists(self.vt_exec_path):
            print(f"Error: VT executable not found at {self.vt_exec_path}")
            raise FileNotFoundError(
                f"VirusTotal executable not found at {self.vt_exec_path}")

        if not self.api_key:
            print("Error: VT_API_KEY not found in environment variables")
            raise ValueError("VT_API_KEY not found in environment variables")
        try:
            init_cmd = [self.vt_exec_path, "init", "-k", self.api_key]
            print(f"Running init command: {' '.join(init_cmd)}")
            process = subprocess.run(
                init_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            print(f"Init command output: {process.stdout}")
            print(f"Init command error: {process.stderr}")
            if process.returncode != 0:
                print(
                    f"Init command failed with return code: {process.returncode}")
                raise RuntimeError(
                    f"Failed to initialize VT CLI: {process.stderr}")
        except Exception as e:
            print(f"Exception during initialization: {str(e)}")
            raise RuntimeError(f"Failed to initialize VT CLI: {str(e)}")

    def scan_file(self, file_path: str) -> Dict[str, Union[str, bool]]:
        print(f"\nScanning file: {file_path}")
        if not os.path.exists(file_path):
            print(f"Error: File not found at {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            print(f"File hash: {file_hash}")

            cmd = [self.vt_exec_path, "scan", "file", file_path]
            print(f"Running scan command: {' '.join(cmd)}")
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            print(f"Scan command output: {process.stdout}")
            print(f"Scan command error: {process.stderr}")
            print(f"Scan command return code: {process.returncode}")

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": process.stderr or "Scan failed",
                }

            scan_id = process.stdout.strip().split('\n')[-1].split()[-1]
            print(f"Extracted scan ID: {scan_id}")
            return {
                "success": True,
                "scan_id": scan_id,
                "sha256": file_hash,
                "message": "File submitted successfully"
            }

        except Exception as e:
            print(f"Exception during scan: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_analysis(self, scan_id: str) -> Dict[str, Union[str, bool, dict]]:
        print(f"\nGetting analysis for scan ID: {scan_id}")
        try:
            cmd = [self.vt_exec_path, "analysis", scan_id, "--format", "json"]
            print(f"Running analysis command: {' '.join(cmd)}")
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            print(f"Analysis command output: {process.stdout}")
            print(f"Analysis command error: {process.stderr}")
            print(f"Analysis command return code: {process.returncode}")

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": process.stderr or "Failed to get analysis"
                }
            try:
                data = json.loads(process.stdout)
                print(f"Parsed JSON data: {json.dumps(data, indent=2)}")

                if isinstance(data, list) and len(data) > 0:
                    data = data[0]
                    print("Extracted first item from data list")

                status = data.get("status", "")
                print(f"Analysis status: {status}")

                if status != "completed":
                    return {
                        "success": False,
                        "error": "Analysis not completed yet",
                        "status": status
                    }

                stats = data.get("stats", {})
                results = data.get("results", {})
                print(f"Analysis stats: {stats}")
                print(f"Analysis results: {results}")

                return {
                    "success": True,
                    "status": status,
                    "stats": stats,
                    "results": results
                }

            except json.JSONDecodeError as e:
                print(f"JSON decode error: {str(e)}")
                print(f"Raw output that failed to parse: {process.stdout}")
                return {
                    "success": False,
                    "error": f"Failed to parse JSON output: {str(e)}"
                }

        except Exception as e:
            print(f"Exception during analysis: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
