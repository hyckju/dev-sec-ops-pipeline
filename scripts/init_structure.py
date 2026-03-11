#!/usr/bin/env python3
"""Initialize Python package structure with __init__.py files"""
import os
from pathlib import Path

def create_init_files():
    """Create __init__.py files in all Python package directories"""
    backend_path = Path(__file__).parent.parent

    # Directories that should have __init__.py
    package_dirs = [
        'app',
        'app/api',
        'app/api/v1',
        'app/core',
        'app/db',
        'app/db/models',
        'app/db/repositories',
        'app/schemas',
        'app/services',
        'app/services/auth',
        'app/services/github',
        'app/services/projects',
        'app/services/pipeline',
        'app/services/pipeline/steps',
        'app/services/security',
        'app/services/deployment',
        'app/services/reports',
        'app/services/dashboard',
        'app/workers',
        'app/integrations',
        'app/integrations/semgrep',
        'app/integrations/docker',
        'app/integrations/nvd',
        'app/integrations/git',
        'app/utils',
        'tests',
        'tests/unit',
        'tests/unit/services',
        'tests/unit/api',
        'tests/unit/utils',
        'tests/integration',
        'tests/integration/github',
        'tests/integration/pipeline',
        'tests/integration/security',
        'tests/integration/deployment',
        'tests/e2e',
        'migrations',
    ]

    for dir_path in package_dirs:
        init_file = backend_path / dir_path / '__init__.py'
        init_file.parent.mkdir(parents=True, exist_ok=True)
        if not init_file.exists():
            init_file.touch()
            print(f"✓ Created {init_file}")
        else:
            print(f"- Skipped {init_file} (already exists)")

if __name__ == '__main__':
    create_init_files()
    print("\n✓ Backend project structure initialized!")
