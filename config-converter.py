#!/usr/bin/env python3
"""
Convert dangerous-functions.yaml to JSON format for Frida consumption
"""

import yaml
import json
import sys
from pathlib import Path

def convert_config(yaml_path, json_path):
    """Convert YAML config to JSON"""
    try:
        with open(yaml_path, 'r') as f:
            config = yaml.safe_load(f)

        with open(json_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✓ Converted {yaml_path} -> {json_path}")
        return True
    except Exception as e:
        print(f"✗ Error converting config: {e}", file=sys.stderr)
        return False

def main():
    script_dir = Path(__file__).parent
    yaml_path = script_dir / "dangerous-functions.yaml"
    json_path = script_dir / "dangerous-functions.json"

    if not yaml_path.exists():
        print(f"✗ Config file not found: {yaml_path}", file=sys.stderr)
        sys.exit(1)

    if convert_config(yaml_path, json_path):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
