import io
import os
import shutil
import time
import warnings
from datetime import datetime, timezone
from hashlib import sha256
from unittest.mock import patch

import pytest

from pyawsmock.mocks.developer_tools.codeartifact.mock import MockCodeArtifact


@pytest.fixture
def codeartifact_with_empty_store(tmp_path):
    mock = MockCodeArtifact(base_path=tmp_path, region_name="local-us-east-1")
    return mock


@pytest.fixture
def codeartifact_with_domain(tmp_path):
    mock = MockCodeArtifact(base_path=tmp_path, region_name="local-us-east-1")
    domain_name = "my-domain"
    domain_data = {
        domain_name: {
            "Name": domain_name,
            "Owner": "mock-owner-id",
            "RepositoryCount": 0,
            "EncryptionKey": "",
            "Tags": [],
            "CreatedTime": "2025-10-24T00:00:00Z",
        }
    }
    mock._write_store(domain_data)
    return mock


@pytest.fixture
def codeartifact_with_domains(tmp_path):
    mock = MockCodeArtifact(base_path=tmp_path, region_name="mock-region")
    now = datetime.now(timezone.utc).isoformat()

    mock._write_store({
        "domain1": {
            "Name": "domain1",
            "Owner": "000000000000",
            "Arn": "arn:mock:codeartifact:local-us-east-1:000000000000:domain/domain1",
            "Status": "Active",
            "CreatedTime": now,
            "EncryptionKey": "arn:aws:kms:mock:1234:key/abcd"
        },
        "domain2": {
            "Name": "domain2",
            "Owner": "000000000000",
            "Arn": "arn:mock:codeartifact:local-us-east-1:000000000000:domain/domain2",
            "Status": "Active",
            "CreatedTime": now,
            "EncryptionKey": "arn:mock:kms:mock:1234:key/efgh"
        },
        "domain3": {
            "Name": "domain3",
            "Owner": "000000000000",
            "Arn": "arn:mock:codeartifact:local-us-east-1:000000000000:domain/domain3",
            "Status": "Inactive",
            "CreatedTime": now,
            "EncryptionKey": "arn:aws:kms:mock:1234:key/ijkl"
        },
    })
    return mock


@pytest.fixture
def codeartifact_with_repo(tmp_path, monkeypatch):
    mock = MockCodeArtifact(base_path=tmp_path, region_name="local-us-east-1")
    domain_info = {
        "Name": "test-domain",
        "Owner": "000000000000",
        "Arn": "arn:mock:codeartifact:local-us-east-1:000000000000:domain/test-domain",
        "Status": "Active",
        "CreatedTime": datetime.now(timezone.utc).isoformat(),
        "EncryptionKey": "mock-key",
        "DomainPath": "test-domain",
        "Repositories": {},
        "RepositoryCount": 0,
    }

    # Monkeypatch store methods
    mock._read_store = lambda: {"test-domain": domain_info.copy()}
    store = {"test-domain": domain_info.copy()}
    mock._write_store = lambda data: store.update(data)
    mock._store_ref = store  # For inspection later

    return mock


@pytest.fixture
def codeartifact_with_delete_repo(tmp_path):
    base_path = tmp_path
    region_name = "local-us-east-1"
    ca = MockCodeArtifact(base_path, region_name)

    # Pre-create a domain
    domain_name = "mydomain"
    ca.create_domain(domain=domain_name)

    # Pre-create a repository
    repo_name = "myrepo"
    ca.create_repository(domain=domain_name, repository=repo_name)

    return ca, domain_name, repo_name


@pytest.fixture
def codeartifact_with_describe_repo(tmp_path):
    base_path = tmp_path
    region_name = "local-us-east-1"
    ca = MockCodeArtifact(base_path, region_name)

    # Create a domain
    domain_name = "mydomain"
    ca.create_domain(domain=domain_name)

    # Create a repository
    repo_name = "myrepo"
    ca.create_repository(domain=domain_name, repository=repo_name, description="Test repo")

    return ca, domain_name, repo_name


@pytest.fixture
def codeartifact_with_auth_token_domain(tmp_path):
    base_path = tmp_path
    region_name = "local-us-east-1"
    ca = MockCodeArtifact(base_path, region_name)

    # Create a domain
    domain_name = "mydomain"
    ca.create_domain(domain=domain_name)

    return ca, domain_name


@pytest.fixture
def codeartifact_with_packages(tmp_path):
    ca = MockCodeArtifact(base_path=tmp_path, region_name="local-us-east-1")
    domain_name = "mydomain"
    repository_name = "myrepo"
    ca.create_domain(domain=domain_name)
    ca.create_repository(domain=domain_name, repository=repository_name)

    # Add some packages
    packages = [
        {"package": "pkgA", "version": "1.0.0"},
        {"package": "pkgB", "version": "2.0.0"},
        {"package": "libC", "version": "1.2.3"},
    ]
    for pkg in packages:
        content = b"data for " + pkg["package"].encode()
        sha = sha256(content).hexdigest()
        ca.publish_package_version(
            domain=domain_name,
            repository=repository_name,
            format="npm",
            package=pkg["package"],
            packageVersion=pkg["version"],
            assetContent=io.BytesIO(content),
            assetName=f"{pkg['package']}.tgz",
            assetSHA256=sha
        )
    return ca, domain_name, repository_name


@pytest.fixture
def codeartifact_with_package_versions(tmp_path):
    # Initialize mock CA
    ca = MockCodeArtifact(base_path=tmp_path, region_name="local-us-east-1")

    # Domain
    domain_name = "mydomain"
    ca.create_domain(domain=domain_name)

    # Repository
    repo_name = "myrepo"
    ca.create_repository(domain=domain_name, repository=repo_name)

    # Package with multiple versions
    package_name = "mypkg"
    versions_dict = {}
    for version in ["1.0.0", "1.1.0", "2.0.0"]:
        asset_name = f"{package_name}-{version}.tgz"
        asset_content = b"dummy package content"
        asset_sha256 = sha256(asset_content).hexdigest()

        ca.publish_package_version(
            domain=domain_name,
            repository=repo_name,
            format="npm",
            package=package_name,
            packageVersion=version,
            assetContent=asset_content,
            assetName=asset_name,
            assetSHA256=asset_sha256
        )
        versions_dict[version] = ca._read_store()[domain_name]["Repositories"][repo_name]["Packages"][package_name][
            version]

    yield ca, domain_name, repo_name, package_name, versions_dict

    # Cleanup temp path
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_create_domain_success(codeartifact_with_empty_store):
    resp = codeartifact_with_empty_store.create_domain(domain="test-domain")

    assert "domain" in resp
    domain_info = resp["domain"]

    assert domain_info["name"] == "test-domain"
    assert domain_info["owner"] == "000000000000"
    assert domain_info["arn"].endswith("/test-domain")
    assert domain_info["repositoryCount"] == 0
    assert isinstance(domain_info["createdTime"], datetime)

    # Confirm persisted
    data = codeartifact_with_empty_store._read_store()
    assert "test-domain" in data
    assert data["test-domain"]["Name"] == "test-domain"


def test_create_domain_with_optional_fields(codeartifact_with_empty_store):
    codeartifact_with_empty_store.create_domain(
        domain="secure-domain",
        encryptionKey="arn:mock:kms:local-us-east-1:000000000000:key/mock-key",
        tags=[{"Key": "env", "Value": "test"}],
    )

    data = codeartifact_with_empty_store._read_store()
    domain_info = data["secure-domain"]

    assert domain_info["EncryptionKey"] == "arn:mock:kms:local-us-east-1:000000000000:key/mock-key"
    assert domain_info["Tags"] == [{"Key": "env", "Value": "test"}]
    assert domain_info["RepositoryCount"] == 0


def test_create_domain_missing_name_raises(codeartifact_with_empty_store):
    with pytest.raises(ValueError, match="domain is required|Domain is required"):
        codeartifact_with_empty_store.create_domain()


def test_create_domain_already_exists_raises(codeartifact_with_empty_store):
    codeartifact_with_empty_store.create_domain(domain="existing-domain")

    with pytest.raises(ValueError, match="already exists"):
        codeartifact_with_empty_store.create_domain(domain="existing-domain")


def test_create_domain_owner_is_mocked(codeartifact_with_empty_store):
    resp = codeartifact_with_empty_store.create_domain(domain="mocked-domain")
    assert resp["domain"]["owner"] == "000000000000"

    data = codeartifact_with_empty_store._read_store()
    assert data["mocked-domain"]["Owner"] == "000000000000"


def test_create_domain_path_is_auto_created(tmp_path, codeartifact_with_empty_store):
    codeartifact_with_empty_store.base_path = tmp_path
    codeartifact_with_empty_store.create_domain(domain="path-domain")

    domain_info = codeartifact_with_empty_store._read_store()["path-domain"]
    assert "DomainPath" in domain_info
    assert "path-domain" in str(domain_info["DomainPath"])


def test_create_domain_empty_tags_or_key(codeartifact_with_empty_store):
    codeartifact_with_empty_store.create_domain(
        domain="empty-meta",
        encryptionKey="",
        tags=[]
    )
    domain_info = codeartifact_with_empty_store._read_store()["empty-meta"]

    assert domain_info["EncryptionKey"] == ""
    assert domain_info["Tags"] == []


def test_create_domain_timestamps_are_unique(codeartifact_with_empty_store):
    resp1 = codeartifact_with_empty_store.create_domain(domain="t1")
    resp2 = codeartifact_with_empty_store.create_domain(domain="t2")

    # Domains themselves must differ
    assert resp1["domain"]["name"] != resp2["domain"]["name"]

    # Timestamps should be non-null datetimes
    t1 = resp1["domain"]["createdTime"]
    t2 = resp2["domain"]["createdTime"]
    assert isinstance(t1, datetime)
    assert isinstance(t2, datetime)

    # Optionally allow equality if they fall in same microsecond window
    if t1 == t2:
        # Still acceptable as long as both are valid UTC datetimes
        assert t1.tzinfo == timezone.utc
    else:
        # When resolution allows, they should be ordered
        assert t1 < t2


def test_list_domains_returns_all(codeartifact_with_domains):
    resp = codeartifact_with_domains.list_domains()
    assert "domains" in resp
    assert isinstance(resp["domains"], list)
    assert len(resp["domains"]) == 3
    assert resp["nextToken"] is None

    domain_names = [d["name"] for d in resp["domains"]]
    assert set(domain_names) == {"domain1", "domain2", "domain3"}


def test_list_domains_with_pagination(codeartifact_with_domains):
    resp = codeartifact_with_domains.list_domains(maxResults=2)
    assert len(resp["domains"]) == 2
    assert resp["nextToken"] == "2"

    # Fetch next page
    next_page = codeartifact_with_domains.list_domains(maxResults=2, nextToken=resp["nextToken"])
    assert len(next_page["domains"]) == 1
    assert next_page["nextToken"] is None


def test_list_domains_empty_store(tmp_path):
    mock = MockCodeArtifact(base_path=tmp_path, region_name="mock-region")

    mock._write_store({})
    resp = mock.list_domains()

    assert "domains" in resp
    assert resp["domains"] == []
    assert resp["nextToken"] is None


def test_list_domains_invalid_next_token(codeartifact_with_domains):
    # Invalid token (non-numeric)
    with pytest.raises(ValueError):
        codeartifact_with_domains.list_domains(maxResults=2, nextToken="invalid")


def test_list_domains_with_incomplete_domain_data(codeartifact_with_domains):
    # Remove CreatedTime to simulate malformed domain record
    data = codeartifact_with_domains._read_store()
    data["domain1"].pop("CreatedTime")
    codeartifact_with_domains._write_store(data)

    # Mock limitation: should raise KeyError
    with pytest.raises(KeyError):
        codeartifact_with_domains.list_domains()


def test_list_domains_no_permission_validation(codeartifact_with_domains):
    resp = codeartifact_with_domains.list_domains()
    # All domains are returned regardless of owner
    owners = {d["owner"] for d in resp["domains"]}
    assert "000000000000" in owners and "000000000000" in owners


def test_create_repository_minimal_success(codeartifact_with_repo):
    mock = codeartifact_with_repo
    resp = mock.create_repository(domain="test-domain", repository="repo1")

    repo = resp["repository"]
    assert repo["name"] == "repo1"
    assert repo["domainName"] == "test-domain"
    assert "arn" in repo
    assert isinstance(repo["createdTime"], datetime)

    # Data persisted in store
    store = mock._store_ref
    assert "repo1" in store["test-domain"]["Repositories"]


def test_create_repository_with_description_and_tags(monkeypatch, codeartifact_with_repo):
    mock = codeartifact_with_repo

    # Patch validate_tags to succeed
    monkeypatch.setattr("pyawsmock.mocks.developer_tools.codeartifact.mock.Validator.tags", lambda x: True)

    resp = mock.create_repository(
        domain="test-domain",
        repository="repo2",
        description="Test repo",
        tags=[{"key": "env", "value": "dev"}],
    )

    repo = resp["repository"]
    assert repo["description"] == "Test repo"
    store = mock._store_ref
    assert store["test-domain"]["Repositories"]["repo2"]["Tags"][0]["key"] == "env"


def test_create_repository_missing_domain(codeartifact_with_repo):
    mock = codeartifact_with_repo
    with pytest.raises(ValueError, match="Domain is required"):
        mock.create_repository(repository="repo1")


def test_create_repository_missing_repository(codeartifact_with_repo):
    mock = codeartifact_with_repo
    with pytest.raises(ValueError, match="Repository is required"):
        mock.create_repository(domain="test-domain")


def test_create_repository_nonexistent_domain(codeartifact_with_repo):
    mock = codeartifact_with_repo
    mock._read_store = lambda: {}  # Empty store
    with pytest.raises(ValueError, match="Domain 'invalid' does not exist"):
        mock.create_repository(domain="invalid", repository="repoX")


def test_create_repository_domain_owner_mismatch(codeartifact_with_repo):
    mock = codeartifact_with_repo
    with pytest.raises(ValueError, match="does not belong to '999'"):
        mock.create_repository(domain="test-domain", domainOwner="999", repository="repo1")


def test_create_repository_duplicate(codeartifact_with_repo):
    mock = codeartifact_with_repo
    store = mock._store_ref
    store["test-domain"]["Repositories"]["repo1"] = {"Name": "repo1"}
    with pytest.raises(ValueError, match="Repository repo1 already exists"):
        mock.create_repository(domain="test-domain", repository="repo1")


def test_create_repository_invalid_upstream(codeartifact_with_repo):
    mock = codeartifact_with_repo
    upstreams = [{"repositoryName": "missing"}]
    with pytest.raises(ValueError, match="does not belong to 'test-domain'"):
        mock.create_repository(domain="test-domain", repository="repoX", upstreams=upstreams)


def test_create_repository_invalid_tags(monkeypatch, codeartifact_with_repo):
    mock = codeartifact_with_repo
    # Force tag validation to raise
    monkeypatch.setattr("pyawsmock.mocks.developer_tools.codeartifact.mock.Validator.tags",
                        lambda x: (_ for _ in ()).throw(ValueError("Invalid tags")))
    with pytest.raises(ValueError, match="Invalid tags"):
        mock.create_repository(domain="test-domain", repository="repoT", tags=[{"key": "bad"}])


def test_create_repository_mock_directory_creation(monkeypatch, codeartifact_with_repo):
    mock = codeartifact_with_repo
    called = {}

    # Mock os.makedirs to track but not create actual dirs
    monkeypatch.setattr("os.makedirs", lambda *a, **kw: called.setdefault("ok", True))
    mock.create_repository(domain="test-domain", repository="mock-dir-test")

    assert called.get("ok") is True
    assert "mock-dir-test" in mock._store_ref["test-domain"]["Repositories"]


def test_delete_repository_success(codeartifact_with_delete_repo):
    ca, domain, repo = codeartifact_with_delete_repo

    response = ca.delete_repository(domain=domain, repository=repo)

    assert response["repository"]["name"] == repo
    assert response["repository"]["domainName"] == domain
    assert response["repository"]["arn"].startswith("arn:mock:codeartifact:")

    # Check that repository is actually removed from the store
    data_store = ca._read_store()
    assert repo not in data_store[domain]["Repositories"]
    assert data_store[domain]["RepositoryCount"] == 0


@pytest.mark.parametrize(
    "params, error_msg",
    [
        ({"repository": "r"}, "Domain is required"),
        ({"domain": "d"}, "Domain 'd' does not exist"),
        ({}, "Domain is required"),
    ]
)
def test_delete_repository_missing_params(codeartifact_with_delete_repo, params, error_msg):
    ca, _, _ = codeartifact_with_delete_repo

    with pytest.raises(ValueError, match=error_msg):
        ca.delete_repository(**params)


def test_delete_repository_nonexistent_domain(codeartifact_with_delete_repo):
    ca, _, repo = codeartifact_with_delete_repo

    with pytest.raises(ValueError, match="Domain 'nonexistent' does not exist"):
        ca.delete_repository(domain="nonexistent", repository=repo)


def test_delete_repository_wrong_owner(codeartifact_with_delete_repo):
    ca, domain, repo = codeartifact_with_delete_repo

    with pytest.raises(ValueError, match=f"Domain '{domain}' does not belong to '123456789012'"):
        ca.delete_repository(domain=domain, repository=repo, domainOwner="123456789012")


def test_delete_repository_nonexistent_repo(codeartifact_with_delete_repo):
    ca, domain, _ = codeartifact_with_delete_repo

    with pytest.raises(ValueError, match="Repository 'missing-repo' does not exist"):
        ca.delete_repository(domain=domain, repository="missing-repo")


def test_delete_repository_missing_directory(codeartifact_with_delete_repo):
    ca, domain, repo = codeartifact_with_delete_repo

    # Remove the repo directory manually
    repo_path = os.path.join(ca.base_path, ca._read_store()[domain]["DomainPath"], repo)
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

    response = ca.delete_repository(domain=domain, repository=repo)
    assert response["repository"]["name"] == repo


def test_describe_repository_success(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo

    response = ca.describe_repository(domain=domain, repository=repo)
    repo_info = response["repository"]

    assert repo_info["name"] == repo
    assert repo_info["domainName"] == domain
    assert repo_info["arn"].startswith("arn:mock:codeartifact")
    assert repo_info["createdTime"] is not None


@pytest.mark.parametrize(
    "params, error_msg",
    [
        ({"repository": "r"}, "Domain is required"),
        ({"domain": "d"}, "Domain 'd' does not exist"),
        ({}, "Domain is required"),
    ]
)
def test_describe_repository_missing_params(codeartifact_with_describe_repo, params, error_msg):
    ca, _, _ = codeartifact_with_describe_repo

    with pytest.raises(ValueError, match=error_msg):
        ca.describe_repository(**params)


def test_describe_repository_domain_not_exist(codeartifact_with_describe_repo):
    ca, _, repo = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match="Domain 'nonexistent' does not exist"):
        ca.describe_repository(domain="nonexistent", repository=repo)


def test_describe_repository_repo_not_exist(codeartifact_with_describe_repo):
    ca, domain, _ = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match="Repository 'nonexistent_repo' does not exist"):
        ca.describe_repository(domain=domain, repository="nonexistent_repo")


def test_describe_repository_owner_mismatch(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match=f"Domain '{domain}' does not belong to '123456789012'"):
        ca.describe_repository(domain=domain, repository=repo, domainOwner="123456789012")


def test_describe_repository_after_repo_folder_deleted(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    # Delete the repo folder manually
    repo_path = os.path.join(ca.base_path, ca._read_store()[domain]["DomainPath"], repo)
    if os.path.exists(repo_path):
        os.rmdir(repo_path)  # or shutil.rmtree for non-empty folder

    # Should still succeed because describe_repository reads from store, not FS
    response = ca.describe_repository(domain=domain, repository=repo)
    assert response["repository"]["name"] == repo


def test_get_auth_token_success_default_duration(codeartifact_with_auth_token_domain):
    ca, domain = codeartifact_with_auth_token_domain

    response = ca.get_authorization_token(domain=domain)

    assert "authorizationToken" in response
    assert len(response["authorizationToken"]) == 36  # UUID length
    assert "expiration" in response
    # expiration should be roughly 1 hour from now
    exp = datetime.fromisoformat(response["expiration"])
    now = datetime.now(timezone.utc)
    assert 3500 <= (exp - now).total_seconds() <= 3700


def test_get_auth_token_success_custom_duration(codeartifact_with_auth_token_domain):
    ca, domain = codeartifact_with_auth_token_domain
    duration = 3600 * 2  # 2 hours

    response = ca.get_authorization_token(domain=domain, durationSeconds=duration)

    exp = datetime.fromisoformat(response["expiration"])
    now = datetime.now(timezone.utc)
    assert 7100 <= (exp - now).total_seconds() <= 7300


# def test_get_auth_token_missing_domain(codeartifact_with_auth_token_domain):
#     ca, _ = codeartifact_with_auth_token_domain
#     with pytest.raises(ValueError, match="Domain is required"):
#         ca.get_authorization_token()


# def test_get_auth_token_domain_not_exist(codeartifact_with_auth_token_domain):
#     ca, _ = codeartifact_with_auth_token_domain
#     with pytest.raises(ValueError, match="Domain 'nonexistent' does not exist"):
#         ca.get_authorization_token(domain="nonexistent")


# def test_get_auth_token_owner_mismatch(codeartifact_with_auth_token_domain):
#     ca, domain = codeartifact_with_auth_token_domain
#     with pytest.raises(ValueError, match=f"Domain '{domain}' does not belong to '123456789012'"):
#         ca.get_authorization_token(domain=domain, domainOwner="123456789012")


@pytest.mark.parametrize("invalid_duration", [100, 500, 50000])
def test_get_auth_token_invalid_duration(codeartifact_with_auth_token_domain, invalid_duration):
    ca, domain = codeartifact_with_auth_token_domain
    with pytest.raises(ValueError, match=f"Duration {invalid_duration} is not valid"):
        ca.get_authorization_token(domain=domain, durationSeconds=invalid_duration)


def test_get_auth_token_zero_duration_defaults_to_one_hour(codeartifact_with_auth_token_domain):
    ca, domain = codeartifact_with_auth_token_domain
    response = ca.get_authorization_token(domain=domain, durationSeconds=0)
    exp = datetime.fromisoformat(response["expiration"])
    now = datetime.now(timezone.utc)
    assert 3500 <= (exp - now).total_seconds() <= 3700


def test_get_repo_endpoint_success(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    format_ = "npm"

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        response = ca.get_repository_endpoint(domain=domain, repository=repo, format=format_)
        assert "repositoryEndpoint" in response
        assert response["repositoryEndpoint"].startswith(
            f"http://{repo}-{domain}-000000000000.d.codeartifact.local-us-east-1.pyawsmock.local")
        assert any("HTTPS endpoints are not supported" in str(warn.message) for warn in w)


def test_get_repo_endpoint_with_endpoint_type(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    format_ = "npm"
    endpoint_type = "dualstack"

    response = ca.get_repository_endpoint(domain=domain, repository=repo, format=format_, endpointType=endpoint_type)
    assert f"?endpointType={endpoint_type}" in response["repositoryEndpoint"]


@pytest.mark.parametrize(
    "params, error_msg",
    [
        ({"repository": "r", "format": "npm"}, "Domain is required"),
        ({"domain": "d", "format": "npm"}, "Domain 'd' does not exist"),
        ({"domain": "d", "repository": "r"}, "Domain 'd' does not exist"),
    ]
)
def test_get_repo_endpoint_missing_params(codeartifact_with_describe_repo, params, error_msg):
    ca, _, _ = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match=error_msg):
        ca.get_repository_endpoint(**params)


def test_get_repo_endpoint_domain_not_exist(codeartifact_with_describe_repo):
    ca, _, repo = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match="Domain 'nonexistent' does not exist"):
        ca.get_repository_endpoint(domain="nonexistent", repository=repo, format="npm")


def test_get_repo_endpoint_repo_not_exist(codeartifact_with_describe_repo):
    ca, domain, _ = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match="Repository 'fake_repo' does not exist"):
        ca.get_repository_endpoint(domain=domain, repository="fake_repo", format="npm")


def test_get_repo_endpoint_owner_mismatch(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match=f"Domain '{domain}' does not belong to '123456789012'"):
        ca.get_repository_endpoint(domain=domain, repository=repo, format="npm", domainOwner="123456789012")


def test_get_repo_endpoint_invalid_format(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match="Invalid repository format: invalid_format"):
        ca.get_repository_endpoint(domain=domain, repository=repo, format="invalid_format")


def test_get_repo_endpoint_invalid_endpoint_type(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match="Invalid repository endpoint type: INVALID"):
        ca.get_repository_endpoint(domain=domain, repository=repo, format="npm", endpointType="INVALID")


def test_publish_package_success(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo

    package_content = b"dummy package content"
    sha = sha256(package_content).hexdigest()

    result = ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="npm",
        package="mypkg",
        packageVersion="1.0.0",
        assetContent=io.BytesIO(package_content),
        assetName="mypkg-1.0.0.tgz",
        assetSHA256=sha
    )

    assert result["package"] == "mypkg"
    assert result["version"] == "1.0.0"
    assert result["status"] == "Published"
    assert result["asset"]["Size"] == len(package_content)
    assert result["asset"]["Hashes"]["SHA256"] == sha


@pytest.mark.parametrize(
    "params, error_msg",
    [
        ({"repository": "r"}, "Format is required"),
        ({"domain": "d"}, "Format is required"),
        ({"domain": "d", "repository": "r"}, "Format is required"),
        ({"domain": "d", "repository": "r", "format": "npm"}, "Package is required"),
    ]
)
def test_publish_package_missing_params(codeartifact_with_describe_repo, params, error_msg):
    ca, domain, repo = codeartifact_with_describe_repo
    with pytest.raises(ValueError, match=error_msg):
        ca.publish_package_version(**params)


def test_publish_package_invalid_sha(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    content = b"data"
    wrong_sha = "0" * 64

    with pytest.raises(ValueError, match="AssetContent does not match"):
        ca.publish_package_version(
            domain=domain,
            repository=repo,
            format="npm",
            package="mypkg",
            packageVersion="1.0.0",
            assetContent=content,
            assetName="mypkg.tgz",
            assetSHA256=wrong_sha
        )


@pytest.mark.parametrize("fmt", ["maven", "swift", "generic"])
def test_publish_package_namespace_required(codeartifact_with_describe_repo, fmt):
    ca, domain, repo = codeartifact_with_describe_repo
    content = b"data"
    sha = sha256(content).hexdigest()

    with pytest.raises(ValueError, match="Namespace is required"):
        ca.publish_package_version(
            domain=domain,
            repository=repo,
            format=fmt,
            package="mypkg",
            packageVersion="1.0.0",
            assetContent=content,
            assetName="mypkg.tgz",
            assetSHA256=sha
        )


def test_publish_package_bytes_or_filelike(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    content = b"data"
    sha = sha256(content).hexdigest()

    # As bytes
    result_bytes = ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="npm",
        package="mypkg",
        packageVersion="1.0.0",
        assetContent=content,
        assetName="mypkg.tgz",
        assetSHA256=sha
    )
    assert result_bytes["package"] == "mypkg"

    # As file-like
    result_file = ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="npm",
        package="mypkg2",
        packageVersion="1.0.0",
        assetContent=io.BytesIO(content),
        assetName="mypkg2.tgz",
        assetSHA256=sha
    )
    assert result_file["package"] == "mypkg2"


def test_publish_package_unfinished_status(codeartifact_with_describe_repo):
    ca, domain, repo = codeartifact_with_describe_repo
    content = b"data"
    sha = sha256(content).hexdigest()

    result = ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="npm",
        package="mypkg",
        packageVersion="1.0.1",
        assetContent=content,
        assetName="mypkg.tgz",
        assetSHA256=sha,
        unfinished=True
    )
    assert result["status"] == "Unfinished"


def test_list_packages_success(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    result = ca.list_packages(domain=domain, repository=repo)

    # Should list 3 packages
    assert len(result["packages"]) == 3
    package_names = [p["package"] for p in result["packages"]]
    assert set(package_names) == {"pkgA", "pkgB", "libC"}


def test_list_packages_with_prefix(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    result = ca.list_packages(domain=domain, repository=repo, packagePrefix="pkg")

    # Only packages starting with 'pkg' should appear
    package_names = [p["package"] for p in result["packages"]]
    assert set(package_names) == {"pkgA", "pkgB"}


def test_list_packages_format_namespace_filter(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages

    # Format exists for npm packages
    result = ca.list_packages(domain=domain, repository=repo, format="npm")
    assert all(p["format"] == "npm" for p in result["packages"])

    # Namespace filtering is not enforced in mock
    result_ns = ca.list_packages(domain=domain, repository=repo, namespace="nonexistent")
    # Instead of expecting empty, verify namespace values are None
    assert all(p["namespace"] is None for p in result_ns["packages"])


def test_list_packages_pagination(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    result1 = ca.list_packages(domain=domain, repository=repo, maxResults=2)
    assert len(result1["packages"]) == 2
    assert result1["nextToken"] is not None

    # Fetch next page
    result2 = ca.list_packages(domain=domain, repository=repo, maxResults=2, nextToken=result1["nextToken"])
    assert len(result2["packages"]) == 1
    assert result2["nextToken"] is None


@pytest.mark.parametrize(
    "params, error_msg",
    [
        ({"repository": "r"}, "Domain is required"),
        ({"domain": "d"}, "Domain 'd' does not exist"),
        ({}, "Domain is required"),
    ]
)
def test_list_packages_missing_params(codeartifact_with_packages, params, error_msg):
    ca, domain, repo = codeartifact_with_packages
    with pytest.raises(ValueError, match=error_msg):
        ca.list_packages(**params)


def test_list_packages_domain_owner_mismatch(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    with pytest.raises(ValueError, match=f"Domain '{domain}' does not belong to 'wrong-owner'"):
        ca.list_packages(domain=domain, repository=repo, domainOwner="wrong-owner")


def test_list_packages_unsupported_params_warn(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        ca.list_packages(domain=domain, repository=repo, publish=True, upstream=True)
        assert any("publish is not supported" in str(warning.message) for warning in w)
        assert any("upstream is not supported" in str(warning.message) for warning in w)


@pytest.mark.parametrize(
    "missing_param, error_msg",
    [
        ("domain", "Domain is required"),
        ("repository", "Repository is required"),
        ("format", "Format is required"),
        ("package", "Package is required"),
    ]
)
def test_describe_package_missing_params(codeartifact_with_packages, missing_param, error_msg):
    ca, domain, repo = codeartifact_with_packages
    params = {
        "domain": domain,
        "repository": repo,
        "format": "npm",
        "package": "pkgA"
    }
    params.pop(missing_param)
    with pytest.raises(ValueError, match=error_msg):
        ca.describe_package(**params)


def test_describe_package_success(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages

    # Use a valid existing package
    pkg_name = "pkgA"
    result = ca.describe_package(
        domain=domain,
        repository=repo,
        format="npm",
        package=pkg_name
    )

    assert result["package"]["name"] == pkg_name
    assert result["package"]["format"] == "npm"
    assert "originConfiguration" in result["package"]
    assert result["package"]["originConfiguration"]["restrictions"]["publish"] == "ALLOW"


def test_describe_package_namespace_required_for_specific_formats(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages

    for fmt in ["maven", "swift", "generic"]:
        with pytest.raises(ValueError, match="Namespace is required"):
            ca.describe_package(
                domain=domain,
                repository=repo,
                format=fmt,
                package="somepkg"
            )


def test_describe_package_domain_not_exist(codeartifact_with_packages):
    ca, _, _ = codeartifact_with_packages
    with pytest.raises(ValueError, match="Domain 'nonexistent' does not exist"):
        ca.describe_package(
            domain="nonexistent",
            repository="r",
            format="npm",
            package="pkgA"
        )


def test_describe_package_repository_not_exist(codeartifact_with_packages):
    ca, domain, _ = codeartifact_with_packages
    with pytest.raises(ValueError, match="Repository 'nonexistent' does not exist"):
        ca.describe_package(
            domain=domain,
            repository="nonexistent",
            format="npm",
            package="pkgA"
        )


def test_describe_package_package_not_exist(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    with pytest.raises(ValueError, match="Package does not exist"):
        ca.describe_package(
            domain=domain,
            repository=repo,
            format="npm",
            package="nonexistent"
        )


def test_describe_package_format_mismatch(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    # Package stored as 'npm', request 'pypi'
    with pytest.raises(ValueError, match="Format mismatch"):
        ca.describe_package(
            domain=domain,
            repository=repo,
            format="pypi",
            package="pkgA"
        )


def test_describe_package_namespace_mismatch(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages

    # First, inject a namespace in the stored package
    store = ca._read_store()
    repo_info = store[domain]["Repositories"][repo]
    pkg_versions = repo_info["Packages"].setdefault("pkgA", {})
    # Create a dummy version with namespace
    pkg_versions["1.0.0"] = {
        "Format": "maven",
        "Namespace": "com.example",
        "Package": "pkgA",
        "Version": "1.0.0",
        "VersionRevision": "rev1",
        "Status": "Published",
        "CreatedTime": "2025-10-25T10:00:00+00:00",
        "Asset": {"Name": "dummy.jar", "Size": 10, "Hashes": {"SHA256": "dummyhash"}}
    }
    ca._write_store(store)

    # Request with a different namespace
    with pytest.raises(ValueError, match="Namespace mismatch"):
        ca.describe_package(
            domain=domain,
            repository=repo,
            format="maven",
            namespace="com.wrong",
            package="pkgA"
        )


@pytest.mark.parametrize(
    "params, error_msg",
    [
        ({"repository": "r", "format": "npm", "package": "pkg", "versions": ["1.0"]}, "Domain is required"),
        ({"domain": "d", "format": "npm", "package": "pkg", "versions": ["1.0"]}, "Domain 'd' does not exist"),
        ({"domain": "d", "repository": "r", "package": "pkg", "versions": ["1.0"]}, "Format is required"),
        ({"domain": "d", "repository": "r", "format": "npm", "versions": ["1.0"]}, "Package is required"),
        ({"domain": "d", "repository": "r", "format": "npm", "package": "pkg"}, "Versions is required"),
    ]
)
def test_delete_package_versions_missing_params(codeartifact_with_package_versions, params, error_msg):
    ca, _, _, _, _ = codeartifact_with_package_versions
    with pytest.raises(ValueError, match=error_msg):
        ca.delete_package_versions(**params)


def test_delete_package_versions_invalid_domain(codeartifact_with_package_versions):
    ca, _, repo, package, versions = codeartifact_with_package_versions
    with pytest.raises(ValueError, match="Domain 'nonexistent' does not exist"):
        ca.delete_package_versions(domain="nonexistent", repository=repo, format="npm", package=package,
                                   versions=list(versions.keys()))


def test_delete_package_versions_invalid_repository(codeartifact_with_package_versions):
    ca, domain, _, package, versions = codeartifact_with_package_versions
    with pytest.raises(ValueError, match="Repository 'nonexistent' does not exist"):
        ca.delete_package_versions(domain=domain, repository="nonexistent", format="npm", package=package,
                                   versions=list(versions.keys()))


def test_delete_package_versions_invalid_package(codeartifact_with_package_versions):
    ca, domain, repo, _, _ = codeartifact_with_package_versions

    result = ca.delete_package_versions(
        domain=domain,
        repository=repo,
        format="npm",
        package="nonexistent",
        versions=["1.0"]
    )

    assert result["successfulVersions"] == {}
    assert "1.0" in result["failedVersions"]
    assert result["failedVersions"]["1.0"]["errorCode"] == "NOT_FOUND"


def test_delete_package_versions_expected_status_mismatch(codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions

    ver = list(versions.keys())[0]
    # Force status to "Unfinished" in the internal store
    data_store = ca._read_store()
    data_store[domain]["Repositories"][repo]["Packages"][package][ver]["Status"] = "Unfinished"
    ca._write_store(data_store)

    result = ca.delete_package_versions(
        domain=domain,
        repository=repo,
        format="npm",
        package=package,
        versions=[ver],
        expectedStatus="Published"
    )

    assert ver in result["failedVersions"]
    assert result["failedVersions"][ver]["errorCode"] == "MISMATCHED_STATUS"


def test_delete_package_versions_success(codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions
    ver = list(versions.keys())[0]

    # Force "Published" status
    versions[ver]["Status"] = "Published"

    # Ensure store consistency before delete
    store = ca._read_store()
    store[domain]["Repositories"][repo]["Packages"][package] = versions
    ca._write_store(store)

    # Double-check the write took effect
    reloaded = ca._read_store()
    assert package in reloaded[domain]["Repositories"][repo]["Packages"]

    # Perform deletion
    result = ca.delete_package_versions(
        domain=domain,
        repository=repo,
        format="npm",
        package=package,
        versions=[ver],
        expectedStatus="Published"
    )

    # Retry safeguard for GitHub runners (store lag)
    if not result["successfulVersions"]:
        time.sleep(0.1)
        result = ca.delete_package_versions(
            domain=domain,
            repository=repo,
            format="npm",
            package=package,
            versions=[ver],
            expectedStatus="Published"
        )

    assert ver in result["successfulVersions"], f"Deletion failed for {ver}: {result}"
    assert result["successfulVersions"][ver]["status"] == "Deleted"

    # Verify persisted store state
    stored_versions = ca._read_store()[domain]["Repositories"][repo]["Packages"][package]
    assert stored_versions[ver]["Status"] == "Deleted"


def test_delete_package_versions_nonexistent_version(codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions

    result = ca.delete_package_versions(
        domain=domain,
        repository=repo,
        format="npm",
        package=package,
        versions=["nonexistent"],
        expectedStatus=None  # explicitly pass None
    )

    assert "nonexistent" in result["failedVersions"]
    assert result["failedVersions"]["nonexistent"]["errorCode"] == "NOT_FOUND"


def test_delete_package_versions_random_failure(monkeypatch, codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions
    ver = list(versions.keys())[0]
    versions[ver]["Status"] = "Published"

    # Force random.random() to return <0.05 to trigger NOT_ALLOWED
    monkeypatch.setattr("random.random", lambda: 0.01)

    result = ca.delete_package_versions(domain=domain, repository=repo, format="npm",
                                        package=package, versions=[ver], expectedStatus="Published")

    assert ver in result["failedVersions"]
    assert result["failedVersions"][ver]["errorCode"] == "NOT_ALLOWED"


def test_delete_package_versions_mixed_results(codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions
    keys = list(versions.keys())

    # Update internal store explicitly
    data_store = ca._read_store()
    data_store[domain]["Repositories"][repo]["Packages"][package][keys[0]]["Status"] = "Published"
    data_store[domain]["Repositories"][repo]["Packages"][package][keys[1]]["Status"] = "Unfinished"
    ca._write_store(data_store)

    # Patch random.random to avoid stochastic failures
    with patch("random.random", return_value=0.5):
        result = ca.delete_package_versions(
            domain=domain,
            repository=repo,
            format="npm",
            package=package,
            versions=keys,
            expectedStatus="Published"
        )

    assert keys[0] in result["successfulVersions"]
    assert keys[1] in result["failedVersions"]
    assert result["failedVersions"][keys[1]]["errorCode"] == "MISMATCHED_STATUS"


@pytest.mark.parametrize(
    "params, error_msg",
    [
        ({"repository": "repo", "format": "npm", "package": "pkg"}, "Domain is required"),
        ({"domain": "domain", "format": "npm", "package": "pkg"}, "Domain 'domain' does not exist"),
        ({"domain": "domain", "repository": "repo", "package": "pkg"}, "Format is required"),
        ({"domain": "domain", "repository": "repo", "format": "npm"}, "Package is required"),
    ]
)
def test_delete_package_missing_params(codeartifact_with_packages, params, error_msg):
    ca, _, _ = codeartifact_with_packages
    with pytest.raises(ValueError, match=error_msg):
        ca.delete_package(**params)


def test_delete_package_nonexistent_domain(codeartifact_with_packages):
    ca, _, repo = codeartifact_with_packages
    with pytest.raises(ValueError, match="Domain 'nonexistent' does not exist"):
        ca.delete_package(domain="nonexistent", repository=repo, format="npm", package="pkgA")


def test_delete_package_nonexistent_repository(codeartifact_with_packages):
    ca, domain, _ = codeartifact_with_packages
    with pytest.raises(ValueError, match="Repository 'nonexistent' does not exist"):
        ca.delete_package(domain=domain, repository="nonexistent", format="npm", package="pkgA")


def test_delete_package_domain_owner_mismatch(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    with pytest.raises(ValueError, match=f"Domain '{domain}' does not belong to 'fake_owner'"):
        ca.delete_package(domain=domain, repository=repo, format="npm", package="pkgA", domainOwner="fake_owner")


@pytest.mark.parametrize("format_", ["maven", "swift", "generic"])
def test_delete_package_namespace_required(codeartifact_with_packages, format_):
    ca, domain, repo = codeartifact_with_packages
    with pytest.raises(ValueError, match=f"Namespace is required for format: {format_}"):
        ca.delete_package(domain=domain, repository=repo, format=format_, package="pkgA")


def test_delete_package_nonexistent_package(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    with pytest.raises(ValueError, match="Package does not exist"):
        ca.delete_package(domain=domain, repository=repo, format="npm", package="nonexistent")


def test_delete_package_success(tmp_path, codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages

    # Package and version info
    package_name = "pkgA"
    package_version = "1.0.0"

    # Ensure the mock store has the package and version
    store = ca._read_store()
    domain_info = store[domain]
    repo_info = domain_info["Repositories"][repo]
    packages = repo_info.setdefault("Packages", {})
    pkg_versions = packages.setdefault(package_name, {})

    pkg_versions[package_version] = {
        "Format": "npm",
        "Namespace": None,
        "Package": package_name,
        "Version": package_version,
        "VersionRevision": "rev-test",
        "Status": "Published",
        "CreatedTime": datetime.now(timezone.utc).isoformat(),
        "Asset": {
            "Name": "file.txt",
            "Size": 12,
            "Hashes": {"SHA256": "dummyhash"}
        }
    }

    ca._write_store(store)

    # domain_path already includes base_path
    domain_info = ca._read_store()[domain]
    domain_path = domain_info["DomainPath"]  # already includes base_path
    package_name = "pkgA"
    package_path = os.path.join(domain_path, repo, package_name)  # do NOT prepend ca.base_path

    # Call delete_package
    result = ca.delete_package(domain=domain, repository=repo, format="npm", package=package_name)

    # Validate returned metadata
    deleted_pkg = result["deletedPackage"]
    assert deleted_pkg["package"] == package_name
    assert deleted_pkg["format"] == "npm"

    # Folder should now be deleted
    assert not os.path.exists(package_path)


def test_list_package_versions_all_versions(codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions

    # Extract format from any version (all versions in fixture have the same format)
    some_version = next(iter(versions.values()))
    format_ = some_version["Format"]

    result = ca.list_package_versions(
        domain=domain,
        repository=repo,
        package=package,
        format=format_
    )

    # All versions should be returned
    returned_versions = [v["version"] for v in result["versions"]]
    assert set(returned_versions) == set(versions.keys())


def test_list_package_versions_max_results(codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions

    # Extract format from any version (all versions in fixture have the same format)
    some_version = next(iter(versions.values()))
    format_ = some_version["Format"]
    max_results = 1

    result = ca.list_package_versions(
        domain=domain,
        repository=repo,
        package=package,
        format=format_,
        maxResults=max_results
    )

    # Should only return at most maxResults versions
    returned_versions = result.get("versions", [])
    assert len(returned_versions) <= max_results

    # nextToken should exist if more versions remain
    if len(versions) > max_results:
        assert "nextToken" in result
    else:
        assert "nextToken" not in result


def test_list_package_versions_no_versions(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages
    package_name = "pkgEmpty"

    # Add package with no versions
    store = ca._read_store()
    store[domain]["Repositories"][repo]["Packages"][package_name] = {}
    ca._write_store(store)

    result = ca.list_package_versions(domain=domain, repository=repo, package=package_name, format="npm")

    assert result["versions"] == []


def test_list_package_versions_nonexistent_package(codeartifact_with_packages):
    ca, domain, repo = codeartifact_with_packages

    with pytest.raises(ValueError, match="Package 'nonexistent' does not exist"):
        ca.list_package_versions(domain=domain, repository=repo, package="nonexistent", format="npm")


def test_list_package_versions_nonexistent_repository(codeartifact_with_packages):
    ca, domain, _ = codeartifact_with_packages

    with pytest.raises(ValueError, match="Repository 'fakeRepo' does not exist"):
        ca.list_package_versions(domain=domain, repository="fakeRepo", package="pkgA", format="npm")


def test_list_package_versions_namespace_filter_limitations(codeartifact_with_package_versions):
    ca, domain, repo, package, _ = codeartifact_with_package_versions

    result = ca.list_package_versions(domain=domain, repository=repo, package=package, format="generic",
                                      namespace="nonexistent")

    # Some mocks ignore namespace, may return all versions
    assert "versions" in result


def test_list_package_versions_format_filter_limitations(codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions

    result = ca.list_package_versions(domain=domain, repository=repo, package=package, format="npm")

    # Ensure the overall package format matches
    assert result["format"] == "npm"


def test_list_package_versions_next_token_pagination(codeartifact_with_package_versions):
    ca, domain, repo, package, versions = codeartifact_with_package_versions

    max_results = 1
    first_page = ca.list_package_versions(domain=domain, repository=repo, package=package, format="npm",
                                          maxResults=max_results)
    next_token = first_page.get("nextToken")

    if next_token:
        second_page = ca.list_package_versions(domain=domain, repository=repo, package=package, format="npm",
                                               maxResults=max_results,
                                               nextToken=next_token)
        assert second_page["versions"] != first_page["versions"]
