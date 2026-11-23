"""
Tool-runner wrapper — runs security tools via Docker.

Each tool method supports two modes:
  1. Run the real tool via Docker on the given repo/SBOM path.
  2. Load a pre-generated output file (for tests or when Docker is unavailable).

Never hardcodes paths to any specific repository.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


class ToolRunner:
    """Execute security-scanning tools via Docker and return parsed JSON."""

    # ------------------------------------------------------------------
    # Syft — SBOM generation (CycloneDX JSON)
    # ------------------------------------------------------------------
    @staticmethod
    def run_syft(
        repo_path: str,
        output_path: Optional[str] = None,
        pregenerated: Optional[str] = None,
    ) -> dict:
        """
        Generate a CycloneDX SBOM for *repo_path* using Syft.

        Parameters
        ----------
        repo_path : str
            Absolute path to the repository to scan.
        output_path : str, optional
            Where to write the SBOM JSON.  A temp file is used if omitted.
        pregenerated : str, optional
            Path to an already-generated SBOM file.  When set, Syft is
            skipped and this file is loaded instead.

        Returns
        -------
        dict
            Parsed CycloneDX JSON.
        """
        if pregenerated:
            return _load_json(pregenerated)

        repo_path = str(Path(repo_path).resolve())
        if output_path is None:
            output_path = tempfile.mktemp(suffix=".sbom.cdx.json")

        output_dir = str(Path(output_path).parent.resolve())
        output_name = Path(output_path).name

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{repo_path}:/src:ro",
            "-v", f"{output_dir}:/reports",
            "anchore/syft:latest",
            "dir:/src",
            "-o", f"cyclonedx-json=/reports/{output_name}",
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Syft failed (exit {result.returncode}):\n{result.stderr}")

        return _load_json(output_path)

    # ------------------------------------------------------------------
    # Grype — vulnerability scanning
    # ------------------------------------------------------------------
    @staticmethod
    def run_grype(
        sbom_path: str,
        output_path: Optional[str] = None,
        pregenerated: Optional[str] = None,
    ) -> dict:
        """
        Scan an SBOM for known vulnerabilities using Grype.

        Parameters
        ----------
        sbom_path : str
            Absolute path to the CycloneDX SBOM to scan.
        output_path : str, optional
            Where to write the Grype JSON results.
        pregenerated : str, optional
            Path to an already-generated Grype results file.

        Returns
        -------
        dict
            Parsed Grype JSON output.
        """
        if pregenerated:
            return _load_json(pregenerated)

        sbom_path = str(Path(sbom_path).resolve())
        sbom_dir = str(Path(sbom_path).parent.resolve())
        sbom_name = Path(sbom_path).name

        if output_path is None:
            output_path = tempfile.mktemp(suffix=".grype.json")

        output_dir = str(Path(output_path).parent.resolve())
        output_name = Path(output_path).name

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{sbom_dir}:/input:ro",
            "-v", f"{output_dir}:/reports",
            "anchore/grype:latest",
            f"sbom:/input/{sbom_name}",
            "-o", "json",
            "--file", f"/reports/{output_name}",
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Grype failed (exit {result.returncode}):\n{result.stderr}")

        return _load_json(output_path)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _load_json(path: str) -> dict:
    """Read and parse a JSON file."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

