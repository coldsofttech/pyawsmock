import gzip
import json

from filelock import FileLock


class StoreUtils:
    @staticmethod
    def read_json_gzip(path):
        try:
            with gzip.open(path, "rb") as f:
                return json.loads(f.read().decode("utf-8"))
        except FileNotFoundError:
            return {}

    @staticmethod
    def write_json_gzip(path, data, lock_path):
        lock = FileLock(lock_path)
        with lock:
            with gzip.open(path, "wb") as f:
                f.write(json.dumps(data, indent=4).encode("utf-8"))
