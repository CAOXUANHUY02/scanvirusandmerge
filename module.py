import os
import subprocess
from typing import Dict, Union


class VirusTotalScanner:
    def __init__(self, vt_exec_path: str = "exec/vt.exe"):
        """Initialize VirusTotal scanner with path to VT executable."""
        self.vt_exec_path = vt_exec_path
        if not os.path.exists(vt_exec_path):
            raise FileNotFoundError(
                f"VirusTotal executable not found at {vt_exec_path}")

    def scan_file(self, file_path: str) -> Dict[str, Union[str, bool]]:
        """
        Scan a file using VirusTotal.

        Args:
            file_path: Path to the file to scan

        Returns:
            Dict containing scan results
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            # Execute VT scan command
            cmd = [self.vt_exec_path, "scan", "file", file_path]
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": process.stderr or "Scan failed",
                }

            # The output contains the scan ID in the last line
            # Format: filepath scan_id
            output_lines = process.stdout.strip().split('\n')
            if not output_lines:
                return {
                    "success": False,
                    "error": "No output from scan command"
                }

            # Get the last line and extract the scan ID
            last_line = output_lines[-1].strip()
            parts = last_line.split()

            if len(parts) < 2:
                return {
                    "success": False,
                    "error": "Invalid scan output format"
                }

            scan_id = parts[-1]  # Get the last part which is the scan ID

            return {
                "success": True,
                "scan_id": scan_id,
                "message": "File submitted successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def get_analysis(self, scan_id: str) -> Dict[str, Union[str, bool, dict]]:
        """
        Get analysis results for a previous scan.

        Args:
            scan_id: The scan ID returned from scan_file

        Returns:
            Dict containing analysis results
        """
        try:
            cmd = [self.vt_exec_path, "analysis", scan_id, "format", "--json"]
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": process.stderr or "Failed to get analysis"
                }

            # Parse JSON output
            try:
                import json
                # Lấy phần tử đầu tiên từ mảng JSON
                data = json.loads(process.stdout)[0]

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
