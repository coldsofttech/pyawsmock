import os

import nox

PYTHON_VERSION = "3.10"


@nox.session(python=PYTHON_VERSION)
def lint(session):
    print("🛠️ Running linter")
    try:
        os.remove(".flake8-report")
    except FileNotFoundError:
        pass

    session.install("flake8")
    session.run(
        "flake8",
        "--verbose",
        "--color", "auto",
        "--count",
        "--statistics",
        "--format=default",
        "--output-file=.flake8-report"
    )


@nox.session(python=PYTHON_VERSION)
def test(session):
    print("🧪 Running tests")
    try:
        os.remove(".pytest-results.html")
    except FileNotFoundError:
        pass

    session.install("pytest", "pytest-html")
    session.run(
        "pytest", "tests",
        "-vv", "-rEPW",
        "-o", "pytest_collection_order=alphabetical",
        "--cache-clear",
        "--color=yes",
        "--html=.pytest-results.html", "--self-contained-html"
    )


@nox.session(python=PYTHON_VERSION)
def build(session):
    print("🏗️ Building package")
    session.install("wheel", "setuptools")
    session.run(
        "python", "setup.py", "sdist", "bdist_wheel", external=True
    )

    print("📦 Installing package")
    session.run(
        "python", "-m", "pip", "install", ".", external=True
    )


@nox.session(python=PYTHON_VERSION)
def release_check(session):
    print("📤 Twine Release Check")
    session.install("twine")
    session.run("twine", "check", "dist/*")
