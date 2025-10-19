from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    packages=find_packages(exclude=("tests", "tests.*")),
    long_description=long_description
)
