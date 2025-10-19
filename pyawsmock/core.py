import re
from typing import Optional


def validate_region(region_name: str) -> bool:
    if not isinstance(region_name, str):
        return False

    pattern = r"^local-[a-z]{2}-[a-z]+-\d+$"
    return bool(re.match(pattern, region_name))


def configure_mock(mode: str = "persistent", path: Optional[str] = None):
    from pyawsmock.config import config

    config.init(mode=mode, path=path)


def cleanup_mock():
    from pyawsmock.config import config

    config.cleanup()


def client(service_name, region_name=None, **kwargs):
    if region_name.startswith("local"):
        if validate_region(region_name):
            from pyawsmock.config import config

            if not config.active:
                raise RuntimeError("Mock not configured. Call configure_mock() first.")

            if service_name == "ssm":
                from pyawsmock.mocks.management_and_governance.ssm.mock import MockSSM

                return MockSSM(config.base_path, region_name=region_name)
            else:
                raise NotImplementedError(f"Local Mock not implemented for {service_name}")
        else:
            raise RuntimeError(f"Region {region_name} not supported.")
    else:
        import boto3

        return boto3.client(service_name, region_name=region_name, **kwargs)
