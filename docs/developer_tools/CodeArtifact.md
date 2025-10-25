# 📦 MockCodeArtifact - Local CodeArtifact Mock

**MockCodeArtifact** is a local mock implementation of AWS CodeArtifact, designed for testing and development purposes.
It simulates
repositories, domains, and packages with basic validation, publishing, and listing functionality—without interacting
with the real AWS service.
---

## 🌟 Highlights

- Fully **local, file-based** mock for CodeArtifact.
- Supports domains, repositories, packages, and versions.
- Enables testing **authorization, publishing, and listing workflows**.
- Stores data in **gzip-compressed JSON** for efficiency.
- Paginated listing of domains, packages, and versions.
- Supports basic **upstream and namespace validation**.

---

## 📝 Overview

`MockCodeArtifact` provides an in-memory and filesystem-backed simulation of AWS CodeArtifact for testing purposes. It
is suitable for:

- Local development without AWS credentials.
- CI/CD pipelines where AWS access is limited.
- Unit testing package management workflows.

> ⚠️ **Note**: This is a mock implementation and **does not replicate all AWS CodeArtifact behaviors**, especially
> network endpoints and access control.
---

## 🔑 Key Features

| Feature       | Description                                                                       |
|---------------|-----------------------------------------------------------------------------------|
| Domains       | Create, list, and manage mock CodeArtifact domains.                               |
| Repositories  | Create, describe, delete repositories under a domain.                             |
| Packages      | Publish, list, describe, and delete package versions.                             |
| Authorization | Generate temporary authorization tokens (mocked UUIDs).                           |
| Endpoints     | Provides repository endpoints (HTTP mock only).                                   |
| Pagination    | Supports `maxResults` and `nextToken` for listing APIs.                           |
| Local Storage | Stores all metadata in local JSON (gzip-compressed).                              |
| Validation    | Basic validation for domains, repositories, formats, packages, and SHA256 hashes. |

---

## 🏗️ Instantiation

```python
from pyawsmock import configure_mock, client

# Configure local mock (persistent storage)
configure_mock(mode="persistent", path="./local_ca")

# Create MockCodeArtifact client
ca = client("codeartifact", region_name="local-us-east-1")
```

---

## 🛠️ Methods & Examples

### `create_domain`

```python
resp = ca.create_domain(domain="test-domain", tags=["dev", "mock"])
print(resp)
```

**Return:**

```json
{
  "domain": {
    "name": "test-domain",
    "owner": "000000000000",
    "arn": "arn:mock:codeartifact:us-east-1:000000000000:domain/test-domain",
    "status": "Active",
    "createdTime": "2025-10-22T10:00:00Z",
    "encryptionKey": null,
    "repositoryCount": 0,
    "assetSizeBytes": 0,
    "s3BucketArn": "arn:mock:s3:::test-domain-assets"
  }
}
```

---

### `list_domains`

```python
ca.list_domains(maxResults=10)
```

Returns a paginated list of domains with `nextToken`.
---

### `create_repository`

```python
resp = ca.create_repository(
    domain="test-domain",
    repository="sample-repo",
    description="My sample repository"
)
print(resp)
```

**Return**: Repository metadata including ARN, upstreams, and created time.
---

### `delete_repository`

```python
ca.delete_repository(domain="test-domain", repository="sample-repo")
```

Deletes repository and its contents.
---

### `describe_repository`

```python
ca.describe_repository(domain="test-domain", repository="sample-repo")
```

Returns detailed repository information.
---

### `get_authorization_token`

```python
token_info = ca.get_authorization_token(domain="test-domain")
print(token_info)
```

**Return**

```json
{
  "authorizationToken": "random-uuid",
  "expiration": "2025-10-22T11:00:00Z"
}
```

---

### `get_repository_endpoint`

```python
ca.get_repository_endpoint(domain="test-domain", repository="sample-repo", format="pypi")
```

⚠️ HTTPS endpoints **not supported** in local mock; returns HTTP URL only.
---

### `publish_package_version`

```python
ca.publish_package_version(
    domain="test-domain",
    repository="sample-repo",
    format="pypi",
    package="mockpkg",
    packageVersion="1.0.0",
    assetName="mockpkg-1.0.0.tar.gz",
    assetContent=b"package bytes content",
    assetSHA256="computed_sha256_here"
)
```

Publishes a package version to the repository.
---

### `list_packages`

```python
ca.list_packages(domain="test-domain", repository="sample-repo", format="pypi")
```

Paginated list of all packages in the repository.
---

### `describe_package`

```python
ca.describe_package(domain="test-domain", repository="sample-repo", package="mockpkg", format="pypi")
```

Returns metadata for a single package.
---

### `delete_package_versions`

Deletes specific versions of a package:

```python
ca.delete_package_versions(
    domain="test-domain",
    repository="sample-repo",
    package="mockpkg",
    format="pypi",
    versions=["1.0.0"]
)
```

---

### `delete_package`

Deletes an entire package including all versions:

```python
ca.delete_package(domain="test-domain", repository="sample-repo", package="mockpkg", format="pypi")
```

---

### `list_package_versions`

```python
ca.list_package_versions(
    domain="test-domain",
    repository="sample-repo",
    package="mockpkg",
    format="pypi"
)
```

Returns versions with metadata and optional pagination.
---

## ⚠️ Limitations (Mock-Specific)

- Only **local filesystem storage**; no AWS S3 integration.
- HTTPS endpoints are **not supported**; mock URLs are HTTP only.
- Upstream package resolution is **not functional**.
- Some operations like `publish` or `delete` may have **randomized failures** to simulate restrictions.
- Does **not enforce IAM permissions** or AWS policies.
- Only basic format validation; edge AWS-specific behaviors may not be replicated.
- `assetSHA256` validation required for package publishing.