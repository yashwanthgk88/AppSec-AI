"""
Repository Scanner Service
Handles cloning GitHub repositories and running real security scans
"""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
import re


class RepositoryScanner:
    """Service for cloning and scanning GitHub repositories"""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="appsec_scan_")
        self.repo_path = None

    def clone_repository(self, repo_url: str) -> str:
        """
        Clone a GitHub repository to a temporary directory

        Args:
            repo_url: GitHub repository URL

        Returns:
            Path to cloned repository
        """
        try:
            # Extract repo name from URL
            repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
            self.repo_path = os.path.join(self.temp_dir, repo_name)

            # Clone the repository (shallow clone for speed)
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, self.repo_path],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                raise Exception(f"Failed to clone repository: {result.stderr}")

            return self.repo_path

        except subprocess.TimeoutExpired:
            raise Exception("Repository cloning timed out after 5 minutes")
        except Exception as e:
            self.cleanup()
            raise Exception(f"Error cloning repository: {str(e)}")

    def get_source_files(self, extensions: Optional[List[str]] = None) -> List[str]:
        """
        Get list of source files in the repository

        Args:
            extensions: List of file extensions to filter (e.g., ['.py', '.js'])

        Returns:
            List of file paths
        """
        if not self.repo_path or not os.path.exists(self.repo_path):
            return []

        if extensions is None:
            # Default to common source file extensions
            extensions = [
                '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php',
                '.rb', '.go', '.c', '.cpp', '.h', '.hpp', '.cs',
                '.kt', '.swift', '.rs', '.scala', '.pl', '.sh'
            ]

        source_files = []

        # Directories to skip
        skip_dirs = {
            '.git', 'node_modules', 'venv', 'env', '__pycache__',
            'build', 'dist', 'target', '.vscode', '.idea', 'vendor',
            'bower_components', '.gradle', '.mvn'
        }

        for root, dirs, files in os.walk(self.repo_path):
            # Remove skip directories from the walk
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    full_path = os.path.join(root, file)
                    # Make path relative to repo root
                    rel_path = os.path.relpath(full_path, self.repo_path)
                    source_files.append(full_path)

        return source_files

    def get_dependency_files(self) -> Dict[str, List[str]]:
        """
        Find dependency/package manager files in the repository

        Returns:
            Dictionary mapping package manager type to file paths
        """
        if not self.repo_path or not os.path.exists(self.repo_path):
            return {}

        dependency_files = {
            'npm': [],          # package.json, package-lock.json
            'pip': [],          # requirements.txt, Pipfile, pyproject.toml
            'maven': [],        # pom.xml
            'gradle': [],       # build.gradle, build.gradle.kts
            'composer': [],     # composer.json
            'bundler': [],      # Gemfile
            'go': [],           # go.mod
            'cargo': [],        # Cargo.toml
        }

        for root, dirs, files in os.walk(self.repo_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', 'venv'}]

            for file in files:
                full_path = os.path.join(root, file)

                if file in ['package.json', 'package-lock.json', 'yarn.lock']:
                    dependency_files['npm'].append(full_path)
                elif file in ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py']:
                    dependency_files['pip'].append(full_path)
                elif file == 'pom.xml':
                    dependency_files['maven'].append(full_path)
                elif file in ['build.gradle', 'build.gradle.kts']:
                    dependency_files['gradle'].append(full_path)
                elif file == 'composer.json':
                    dependency_files['composer'].append(full_path)
                elif file == 'Gemfile':
                    dependency_files['bundler'].append(full_path)
                elif file == 'go.mod':
                    dependency_files['go'].append(full_path)
                elif file == 'Cargo.toml':
                    dependency_files['cargo'].append(full_path)

        # Remove empty entries
        return {k: v for k, v in dependency_files.items() if v}

    def get_relative_path(self, full_path: str) -> str:
        """Get relative path from repository root"""
        if self.repo_path and os.path.exists(self.repo_path):
            return os.path.relpath(full_path, self.repo_path)
        return full_path

    def cleanup(self):
        """Clean up temporary directory and cloned repository"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"Warning: Failed to cleanup temp directory: {e}")

    def __del__(self):
        """Cleanup on deletion"""
        self.cleanup()
