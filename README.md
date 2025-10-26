# 🧩 `pyawsmock` - Local AWS Mock Framework

> 🧠 A lightweight, extensible Python package that **mocks AWS services locally** for development and testing - with real
> AWS delegation when needed.

---

## 🚀 Overview

`pyawsmock` emulates popular AWS services locally, allowing developers to **test AWS-dependent applications without
needing cloud connectivity**. It's **boto3-compatible**, automatically delegating API calls to the real AWS SDK when
using non-local regions.

### ✅ Currently Supported Services

| Service                                                                 | Description                                                                    |
|-------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| 🪣 **[S3](docs/storage/S3.md)**                                         | Object storage mock supporting uploads, downloads, metadata, and checksums.    |
| ⚙️ **[SSM Parameter Store](docs/management_and_governance/SSM.md)**     | Local emulation of AWS SSM Parameters with versioning, labels, and encryption. |
| 🧱 **[CodeArtifact](docs/developer_tools/CodeArtifact.md)**             | Domain & repository management with package versioning and mock endpoints.     |
| 🌐 **[CloudFront](docs/networking_and_content_delivery/CloudFront.md)** | Create and manage distributions and origin access identities locally.          |
| 📬 **[SQS](docs/application_integration/SQS.md)**                       | Local emulation of SQS with FIFO support.                                      |

---

## 🧠 Key Features

### 🧭 Local vs AWS Delegation

- Regions starting with `local-*` automatically use **local mock services**.
- Other regions transparently **delegate calls to real AWS** using `boto3`.

### 💾 Persistent & Temporary Storage

- **Persistent mode** — data is stored on disk (for long-term local environments).
- **Temporary mode** — uses an in-memory or temp directory; `cleanup()` removes it automatically.

### 🕓 Audit & Metadata

- Tracks all operations with timestamps.
- Simulates IAM users (`mock-user`) and `arn:mock` identifiers.
- Default mock AWS Account ID: `000000000000`.

### 🔐 SecureString & Encryption Simulation

- For SSM, `SecureString` values are stored base64-encoded.
- Retrieval with `WithDecryption=True` automatically decodes them.

### 🪶 Lightweight & Extensible

- Minimal dependencies (`boto3`, `filelock`, `crcmod`).
- Modular mock architecture — easy to extend to new AWS services.

---

## ⚙️ Installation

### 📦 From PyPI

```bash
pip install pyawsmock
```

### 🧩 From GitHub

```bash
pip install git+https://github.com/coldsofttech/pyawsmock.git
```

### Dependencies

- `boto3~=1.40.55`
- `filelock~=3.20.0`
- `crcmod~=1.7`

> `boto3` is required for delegation to real AWS services.

---

## 🧰 Quick Start Example

```python
from pyawsmock import configure_mock, client, cleanup_mock

# 1️⃣ Configure mock mode
configure_mock(mode="persistent", path="./local_aws")  # Persistent local store
# or
configure_mock(mode="temporary")  # Temporary store

# 2️⃣ Create a local client (SSM)
ssm = client("ssm", region_name="local-eu-west-1")

# 3️⃣ Use it just like boto3
ssm.put_parameter(Name="/demo/key", Value="demo_value", Type="String")

response = ssm.get_parameter(Name="/demo/key")
print(response["Parameter"]["Value"])  # Output: demo_value

# 4️⃣ Cleanup (only for temporary mode)
cleanup_mock()
```

> ⚡ All clients (SSM, S3, SQS, CodeArtifact, CloudFront) use the **same interface as boto3**. Switching between real AWS
> and
> local mock only depends on the region.

## 🧩 Supported Methods

| Service                  | Supported API Calls                                                                                                                                                                                         |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ⚙️ SSM (Parameter Store) | `put_parameter`, `get_parameter`, `get_parameters`, `delete_parameter`, `label_parameter_version`, `unlabel_parameter_version`, `describe_parameters`, `get_parameters_by_path`, `get_parameter_history`    |
| 🪣 S3                    | `create_bucket`, `upload_file`, `download_file`, `get_object`, `create_bucket_metadata_configuration`, `update_bucket_metadata_inventory_table_configuration`, `delete_bucket_metadata_configuration`, etc. |
| 🧱 CodeArtifact          | `create_domain`, `create_repository`, `publish_package_version`, `list_packages`, `delete_package`, `get_authorization_token`, `get_repository_endpoint`, etc.                                              |
| 🌐 CloudFront            | `create_distribution`, `get_distribution`, `get_distribution_config`, `update_distribution`, `delete_distribution`, etc.                                                                                    |
| 📬 SQS                   | `create_queue`, `get_queue_url`, `set_queue_attributes`, `get_queue_attributes`, `list_queues`, `purge_queue`, etc.                                                                                         |

> 🧩 More services coming soon: **API Gateway**, **DynamoDB**, **Lambda**, **CloudWatch**, **Config**, and **CloudTrail
**.

## ⚠️ Known Limitations

- **IAM**, **authentication**, and **permissions** are not enforced.
- **S3 multipart uploads** and full versioning are not implemented yet.
- **CodeArtifact** currently supports only generic asset types and HTTP endpoints.
- **CloudFront** distribution behavior is limited to configuration storage only.
- **SQS** automatic background timers for `DelaySeconds` and `VisibilityTimeout` currently do not exist.

## 🧭 Roadmap

| Status | Feature                                          |
|--------|--------------------------------------------------|
| ✅      | 	SSM, S3, SQS, CodeArtifact, CloudFront support  |
| 🚧     | 	API Gateway, DynamoDB, Lambda, CloudWatch mocks |
| 🚧     | 	IAM simulation with multiple mock users         |
| 🕓     | 	Enhanced audit logging & metrics                |
| 🧩     | 	Multi-account & multi-region persistence        |

## 🤝 Contributing

Contributions are welcome!
To contribute:

1. Fork the repo
2. Create a feature branch
3. Add tests and update docs
4. Submit a pull request

## ⚖️ License

[MIT License](LICENSE)