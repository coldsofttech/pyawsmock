# 🌐 MockCloudFront - Local CloudFront Mock

`MockCloudFront` is a local mock implementation of AWS CloudFront for testing and development. It simulates
distributions and origin access identities (OAIs), allowing developers to test workflows without actual AWS access.

---

## 🌟 Highlights

- ✅ Fully **local, file-based** CloudFront mock.
- 🔒 Supports **Origin Access Identities** (OAI).
- 📦 Supports **distributions** creation, update, deletion, and retrieval.
- 📄 Stores data in **gzip-compressed JSON**.
- 🛠️ Supports basic validation for config, CallerReference, and ETag.
- ⚠️ Includes mock-specific warnings to simulate AWS behaviors.

---

## 📝 Overview

`MockCloudFront` simulates AWS CloudFront functionality locally:

- Create, list, and manage **origin access identities (OAIs)**.
- Create, describe, update, and delete **distributions**.
- Provides **ETag-based concurrency control**.
- Tracks distribution **last modified timestamps**.
- Ideal for local development, unit tests, and CI/CD pipelines without AWS.

> ⚠️ Note: This is a **mock implementation**. It does not perform real network calls or enforce full AWS CloudFront
> behavior.

---

## 🔑 Key Features

| Feature                | Description                                                     |
|------------------------|-----------------------------------------------------------------|
| Origin Access Identity | Create, describe, get config, and delete OAIs.                  |
| Distributions          | Create, update, describe, and delete distributions.             |
| ETag Validation        | Concurrency control for OAIs and distributions.                 |
| Local Storage          | Stores all CloudFront data locally in JSON.                     |
| CallerReference        | Ensures idempotent creation of OAIs and distributions.          |
| Status Tracking        | Tracks distribution status (`Deployed`) and last modified time. |
| Mock Warnings          | Alerts when AWS-specific behaviors are not fully supported.     |

---

## ⚙️ Instantiation

```python
from pyawsmock import configure_mock, client

# Configure local mock (persistent storage)
configure_mock(mode="persistent", path="./local_cf")

# Create MockCloudFront client
cf = client("cloudfront", region_name="local-global")
```

> 🔑 `region_name` must be `local-global` for mock behavior; otherwise it delegates to real AWS.
---

## 🛠️ Methods & Examples

### `create_cloud_front_origin_access_identity`

```python
resp = mock_cf.create_cloud_front_origin_access_identity(
    cf={
        "CallerReference": "unique-string",
        "Comment": "Test OAI"
    }
)
print(resp)
```

Returns:

```json
{
  "CloudFrontOriginAccessIdentity": {
    "Id": "E123ABCDEF45",
    "S3CanonicalUserId": "abc123hash...",
    "CloudFrontOriginAccessIdentityConfig": {
      "CallerReference": "unique-string",
      "Comment": "Test OAI"
    },
    "ETag": "uuid-etag"
  },
  "Location": "/2020-05-31/origin-access-identity/cloudfront/E123ABCDEF45",
  "ETag": "uuid-etag"
}
```

---

### `get_cloud_front_origin_access_identity`

```python
cf.get_cloud_front_origin_access_identity(Id="E123ABCDEF45")
```

Returns detailed OAI metadata.
---

### `get_cloud_front_origin_access_identity_config`

```python
cf.get_cloud_front_origin_access_identity_config(Id="E123ABCDEF45")
```

Returns the OAI configuration (`CallerReference` and `Comment`) with `ETag`.
---

### `delete_cloud_front_origin_access_identity`

```python
cf.delete_cloud_front_origin_access_identity(Id="E123ABCDEF45", IfMatch="uuid-etag")
```

Deletes the OAI after ETag validation.
---

### `create_distribution`

```python
resp = cf.create_distribution(
    DistributionConfig={
        "CallerReference": "dist-unique-123",
        "Enabled": True,
        "Origins": [],
        "DefaultCacheBehavior": {}
    }
)
print(resp)
```

Returns:

```json
{
  "Distribution": {
    "Id": "ED123ABCDEF45",
    "ARN": "arn:mock:cloudfront::000000000000:distribution/ED123ABCDEF45",
    "Status": "Deployed",
    "LastModifiedTime": "2025-10-22T10:00:00Z",
    "DomainName": "ED123ABCDEF45.cloudfront.mock.local",
    "ETag": "uuid-etag",
    "DistributionConfig": {
      ...
    }
  },
  "Location": "/2020-05-31/distribution/ED123ABCDEF45",
  "ETag": "uuid-etag"
}
```

---

### `get_distribution`

```python
cf.get_distribution(Id="ED123ABCDEF45")
```

Returns full distribution metadata including status, domain name, and active trusted signers.
---

### `get_distribution_config`

```python
cf.get_distribution_config(Id="ED123ABCDEF45")
```

Returns only the distribution configuration with `ETag`.
---

### `update_distribution`

```python
cf.update_distribution(
    Id="ED123ABCDEF45",
    IfMatch="uuid-etag",
    DistributionConfig={
        "CallerReference": "dist-unique-123",
        "Enabled": False,
        "Origins": [],
        "DefaultCacheBehavior": {}
    }
)
```

Updates distribution config and generates a new `ETag`.
---

### `delete_distribution`

```python
cf.delete_distribution(Id="ED123ABCDEF45", IfMatch="new-uuid-etag")
```

- Deletes only if distribution is **disabled**.
- Validates `ETag` to prevent race conditions.

---

## ⚠️ Limitations (Mock-Specific)

- 🔒 Only **local JSON storage**; no real AWS integration.
- ⚠️ DistributionConfig validation is **incomplete**; some AWS rules are not enforced.
- ❌ No actual CDN network or cache propagation.
- 🔑 OAIs and distributions **mock ETag-based concurrency**, but do not enforce AWS IAM policies.
- ⚠️ CallerReference ensures idempotency only in the local mock.
- 🚫 HTTPS endpoints or signed URLs are **not supported**.