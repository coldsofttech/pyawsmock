import json
import os
import tempfile
from pathlib import Path
from typing import Optional


class MockConfig:
    SUPPORTED_MODES = ["persistent", "temporary"]

    def __init__(self):
        self.mode = None  # persistent or temporary
        self.base_path = None  # local location to store configurations
        self.active = False
        self.temp_dir = None

    def init(self, mode: str = "persistent", path: Optional[str] = None):
        if mode.lower() not in self.SUPPORTED_MODES:
            raise ValueError("Mode must be one of {}".format(self.SUPPORTED_MODES))

        self.mode = mode.lower()
        if mode == "persistent":
            if not path:
                raise ValueError("Path must be specified when mode is 'persistent'")
            os.makedirs(path, exist_ok=True)
            self.base_path = Path(path).resolve()
        else:
            self.temp_dir = tempfile.TemporaryDirectory(prefix="pyawsmock-")
            self.base_path = Path(self.temp_dir.name).resolve()

        config_file = self.base_path / "mock_config.json"
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump({
                "mode": self.mode,
                "base_path": str(self.base_path)
            }, f, indent=4)

        self.active = True

    def cleanup(self):
        if self.mode == "temporary" and self.temp_dir:
            self.temp_dir.cleanup()


config = MockConfig()
