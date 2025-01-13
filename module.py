import hashlib
import json
import os
import subprocess
from typing import Dict, Union

from dotenv import load_dotenv

load_dotenv()


class VirusTotalScanner:
    def __init__(self, vt_exec_path: str = "vt.exe"):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.vt_exec_path = os.path.join(current_dir, vt_exec_path)
        self.api_key = os.getenv('VT_API_KEY')

        if not os.path.exists(self.vt_exec_path):
            raise FileNotFoundError(
                f"VirusTotal executable not found at {self.vt_exec_path}")

        if not self.api_key:
            raise ValueError("VT_API_KEY not found in environment variables")
        try:
            init_cmd = [self.vt_exec_path, "init", "-k", self.api_key]
            process = subprocess.run(
                init_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            if process.returncode != 0:
                raise RuntimeError(
                    f"Failed to initialize VT CLI: {process.stderr}")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize VT CLI: {str(e)}")

    def scan_file(self, file_path: str) -> Dict[str, Union[str, bool]]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            cmd = [self.vt_exec_path, "scan", "file", file_path]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": process.stderr or "Scan failed",
                }

            return {
                "success": True,
                "scan_id": process.stdout.strip().split('\n')[-1].split()[-1],
                "sha256": file_hash,
                "message": "File submitted successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def get_analysis(self, scan_id: str) -> Dict[str, Union[str, bool, dict]]:
        try:
            cmd = [self.vt_exec_path, "analysis", scan_id, "--format", "json"]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": process.stderr or "Failed to get analysis"
                }
            try:
                data = json.loads(process.stdout)
                if isinstance(data, list) and len(data) > 0:
                    data = data[0]
                return {
                    "success": True,
                    "status": data.get("status", ""),
                    "stats": data.get("stats", {}),
                    "results": data.get("results", {})
                }

            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"Failed to parse JSON output: {str(e)}"
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
