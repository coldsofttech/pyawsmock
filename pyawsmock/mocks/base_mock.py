import re


def validate_region(region_name: str) -> bool:
    if not isinstance(region_name, str):
        return False

    pattern = r"^local-[a-z]{2}-[a-z]+-\d+$"
    return bool(re.match(pattern, region_name))


class MockBase:
    _supported_methods = []

    def __getattr__(self, name):
        if name in self._supported_methods:
            raise NotImplementedError(
                f"The Mock for '{self.__class__.__name__}' declares '{name}' as supported, "
                f"but it's not implemented yet."
            )

        raise AttributeError(
            f"'{self.__class__.__name__}' does not implement '{name}'. "
            f"This operation is not supported in local mock mode."
        )
