import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG_FILE = ".sapyscan.json"

def find_config(start_path: Path) -> Optional[Path]:
    curr = start_path.resolve()
    # If starting path is a file, use its parent directory
    if curr.is_file():
        curr = curr.parent
    for _ in range(5):
        cfg = curr / DEFAULT_CONFIG_FILE
        if cfg.is_file():
            return cfg
        if curr == curr.parent:
            break
        curr = curr.parent
    return None

def load_config(config_path: Optional[Path]) -> Dict[str, Any]:
    if not config_path or not config_path.is_file():
        return {}
    try:
        content = config_path.read_text(encoding="utf-8", errors="ignore")
        return json.loads(content)
    except Exception:
        return {}
