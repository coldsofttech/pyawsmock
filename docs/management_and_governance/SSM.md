# ⚙️ MockSSM — Local SSM Parameter Store Mock

> Part of [pyawsmock](../../README.md) - a fully **local emulation of AWS Systems Manager (SSM) Parameter Store** for
> development and testing.
> Supports versioning, SecureString, labels, filtering, and pagination, with full boto3-compatible objects.

---

## 🌿 Overview

`MockSSM` allows you to **simulate SSM Parameter Store locally**:

- Supports multiple versions per parameter.
- Labels per version for environment-like tagging (e.g., `prod`, `dev`).
- SecureString encryption simulation using base64.
- Filtering, pagination, and history tracking.
- Fully **boto3-compatible**, so switching between local mock and AWS is seamless.

---

## ✨ Key Features

| Feature             | Description                                                             |
|---------------------|-------------------------------------------------------------------------|
| 🧱 Versioning	      | Automatic version increment on parameter updates.                       |
| 🏷️ Labels          | 	Assign human-readable labels to versions (`prod`, `beta`).             |
| 🔐 SecureString     | 	Values encoded in base64; `WithDecryption=True` decodes automatically. |
| 🔎 Filters          | 	Supports `Type`, `KeyId`, `Label`, `AllowedPattern`.                   |
| 📜 Pagination       | 	`MaxResults` and `NextToken` supported for large datasets.             |
| 🧾 History Tracking | 	Modification timestamps and user metadata (`mock-user`).               |
| 💾 Persistence      | 	Store parameters persistently or use temporary mode for testing.       |
| 🪶 Lightweight      | 	Minimal dependencies; uses JSON gzip storage for efficiency.           |

---

## ⚙️ Instantiation

```python
from pyawsmock import configure_mock, client

# Configure local mock (persistent storage)
configure_mock(mode="persistent", path="./local_ssm")

# Create MockSSM client
ssm = client("ssm", region_name="local-us-east-1")
```

> 🔑 `region_name` must start with `local-` for mock behavior; otherwise it delegates to real AWS.
---

## 🧰 Methods & Examples

### `put_parameter`

Create or update a parameter.

```python
ssm.put_parameter(
    Name="/app/db/password",
    Value="super-secret",
    Type="SecureString",
    KeyId="mock-kms-key",
    Overwrite=True,
    Description="Database password",
    Tags=[{"Key": "env", "Value": "prod"}]
)
```

**Returns:**

```json
{
  "Version": 1,
  "Tier": "Standard"
}
```

---

### `get_parameter`

Retrieve a single parameter.

```python
param = ssm.get_parameter(Name="/app/db/password", WithDecryption=True)
print(param["Parameter"]["Value"])  # Output: super-secret
```

**Notes:**

- Supports `:label` syntax to retrieve by version label: `/app/db/password:prod`.

---

### `get_parameters`

Retrieve multiple parameters at once.

```python
ssm.get_parameters(Names=["/app/db/password", "/app/db/user"], WithDecryption=True)
```

**Returns:**

```json
{
  "Parameters": [
    ...
  ],
  "InvalidParameters": [
    ...
  ]
}
```

---

### `get_parameters_by_path`

Retrieve parameters under a path (optionally recursively).

```python
ssm.get_parameters_by_path(
    Path="/app",
    Recursive=True,
    MaxResults=10,
    NextToken=None
)
```

**Features:**

- Supports `ParameterFilters` (e.g., `Type`, `Label`).
- Paginates results with `MaxResults` and `NextToken`.

---

### `get_parameter_by_history`

Retrieve **all versions** of a parameter with metadata.

```python
ssm.get_parameter_history(Name="/app/db/password", WithDecryption=True)
```

**Returns:**
List of versions with `Value`, `Version`, `Labels`, `LastModifiedDate`, `Tier`, etc.
---

### `label_parameter_version`

Add labels to a specific version.

```python
ssm.label_parameter_version(
    Name="/app/db/password",
    ParameterVersion=1,
    Labels=["prod", "stable"]
)
```

**Returns:**

```json
{
  "InvalidLabels": [],
  "ParameterVersion": 1
}
```

---

### `unlabel_parameter_version`

Remove labels from a specific version.

```python
ssm.unlabel_parameter_version(
    Name="/app/db/password",
    ParameterVersion=1,
    Labels=["prod"]
)
```

**Returns:**

```json
{
  "RemovedLabels": [
    "prod"
  ],
  "InvalidLabels": []
}
```

---

### `delete_parameter` & `delete_parameters`

Delete one or multiple parameters.

```python
ssm.delete_parameter(Name="/app/db/password")
ssm.delete_parameters(Names=["/app/db/password", "/app/db/user"])
```

**Returns:**

```json
{
  "DeletedParameters": [
    ...
  ],
  "InvalidParameters": [
    ...
  ]
}
```

---

### `describe_parameters`

Retrieve metadata for parameters, supports filtering & pagination.

```python
ssm.describe_parameters(
    ParameterFilters=[{"Key": "Type", "Option": "Equals", "Values": ["SecureString"]}],
    MaxResults=5
)
```

**Returns:**
List of parameter metadata including `Name`, `Type`, `ARN`, `Version`, `Labels`, etc.
---

## ⚠️ Limitations (Mock-Specific)

- IAM policies, KMS integration, and permissions **not enforced**.
- Labels **must be unique per version**.
- `SecureString` encryption is **base64 only**, not actual KMS.
- Does not support parameter policies or tagging outside of local store.
- `Shared` parameter behavior is **not supported**.
- Multi-region behavior is **simulated**; real AWS behavior may differ.