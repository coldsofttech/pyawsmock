# Local AWS Mock - Python Package (`pyawsmock`)

A lightweight Python package that **mocks AWS services locally** for development and testing. Currently, supports **AWS
Systems Manager (SSM) Parameter Store** and **Amazon S3**, and **AWS CodeArtifact**, including repository management,
package publishing, and version handling.

This package **extends boto3** and automatically delegates calls to real AWS when the region is not a local mock region.

## Key Features

- **Local vs AWS Delegation**
    - Regions starting with `local-*` use the **local mock store**.
    - Other regions delegate calls directory to `boto3` for real AWS services.
- **Persistent or Temporary Storage**
    - **Persistent Mode:** Provide a directory path to store the configurations for local mock across sessions.
    - **Temporary Mode:** Uses a temporary directory (`tempfile`) and supports `cleanup()` to remove temporary data.
- **Audit History**
    - Tracks the IAM user/role performing operations (currently defaults to `mock-user`).
    - Timestamps modifications for audit purposes.
- **ARNs & Account IDs**
    - Uses `arn:mock` instead of `arn:aws` to clearly differentiate local mock resources.
    - Default AWS Account ID is `000000000000` for all mock ARNs.

### SSM Parameter Store Local Mock

- **Versioning & Labels**
    - Supports multiple versions per SSM parameter.
    - Mock implementation of labels per version.
    - Tracks modification history for audit purposes.
- **SecureString Support**
    - Values are stored as `base64` encoded strings.
    - Supports `WithDecryption=True` for retrieval.
- **Filters & Pagination**
    - Supports filters (Type, KeyId, Label) for relevant SSM operations.
    - Handles `MaxResults` and `NextToken` for paginated responses.

### S3 Local Mock

- **Buckets & Objects**
    - Create and manage buckets and objects locally.
- **Checksum Support**
    - Supports `MD5`, `SHA1`, `SHA256`, `CRC32`, `CRC32C`, `CRC64NVME`.
- **Upload & Download**
    - Mimics boto3 `upload_file`, `download_file` with callbacks.
- **StreamingBody**
    - Implements `MockStreamingBody` similar to `botocore`.
- **Transfer Simulation**
    - Supports `MockS3Transfer` and `MockS3TransferConfig` to mimic `S3Transfer` behaviour.
- **Bucket Metadata Configuration**
    - Create, update, retrieve, and delete bucket metadata configuration.
- **Object Retrieval**
    - Supports `get_object` with conditional headers, byte ranges, SSE-C mock headers, and realistic response
      structure.
- **Default Behaviour**
    - Handles versioning (default to `1`), delete markers, storage class, and request payer defaults.
- **Persistent Storage**
    - Stores uploaded files locally for retrieval and S3-like object metadata.

### CodeArtifact Local Mock

- **Domain & Repository Management**
    - `create_domain`, `list_domains`
    - `create_repository`, `delete_repository`, `describe_repository`
- **Authorization & Endpoints**
    - `get_authorization_token`
    - `get_repository_endpoint` (only HTTP, no HTTPS; region not used)
- **Package Versioning**
    - `publish_package_version` (supports versioning, asset content, SHA256)
    - `list_packages`, `describe_package`
    - `list_package_versions`, `delete_package_versions`, `delete_package`
- **Format & Namespace**
    - Format (`npm`, `pypi`, `maven`, `nuget`, `generic`, `ruby`, `swift`, `cargo`) and namespace are stored only at *
      *package version publish time**.
- **Origin Configuration**
    - Not used in the local mock; returned as default empty structure for compatibility.

> **Note:** MOCK_DOMAIN is a placeholder name; it is **not configured** and only returns HTTP endpoints.

## Current Limitations

- **Unsupported AWS Features**
    - Config
    - CloudTrail
    - IAM (Users, Groups, Roles, Policies - permissions are not enforced)
    - Authentication
    - S3 Object Lambda
    - Multi-part downloads via `get_object` or `PartNumber`.
    - Full versioning support for S3 (local mock uses default version `1`)
- **CodeArtifact**
    - Only **generic** asset storage fully supported; format-specific validations are limited.
    - Returns HTTP endpoints only (no HTTPS).
    - `originConfiguration` is not configurable.
- **Default Assumptions**
    - All operations assume a single mock IAM user (`mock-user`).
    - Regions are either `local-*` for mock or real AWS regions for delegation.

> These limitations may be addressed in future versions.

## Supported Services (Current)

| Service               | Methods                                                                                                                                                                                                                                                                                          |
|-----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SSM (Parameter Store) | `put_parameter`, `get_parameter`, `get_parameters`, `delete_parameter`, `label_parameter_version`, `unlabel_parameter_version`, `describe_parameters`, `get_parameters_by_path`, `get_parameter_history`                                                                                         |
| S3                    | `create_bucket`, `create_bucket_metadata_configuration`, `get_bucket_metadata_configuration`, `update_bucket_metadata_inventory_table_configuration`, `update_bucket_metadata_journal_table_configuration`, `delete_bucket_metadata_configuration`, `upload_file`, `download_file`, `get_object` |
| CodeArtifact          | `create_domain`, `list_domains`, `create_repository`, `delete_repository`, `describe_repository`, `get_authorization_token`, `get_repository_endpoint`, `publish_package_version`, `list_packages`, `describe_package`, `delete_package_versions`, `delete_package`, `list_package_versions`     |

> Additional AWS services will be supported in future releases.

## Installation

### From PyPI

```bash
pip install pyawsmock
```

### From GitHub

```bash
pip install git+https://github.com/coldsofttech/pyawsmock.git
```

#### Dependencies

- `boto3~=1.40.55`
- `filelock~=3.20.0`
- `crcmod~=1.7`

> `boto3` is required to delegate calls to real AWS.

## Usage Example

```python
from pyawsmock import configure_mock, client, cleanup_mock

configure_mock(mode="persistent", path="./local_aws")  # Persistent storage example
configure_mock(mode="temporary")  # Temporary storage example

ssm = client("ssm", region_name="local-eu-west-1")  # eu-west-1 region local mock for SSM
ssm.put_parameter(
    Name="/test/key",
    Value="test_value",
    Type="String"
)

response = ssm.get_parameter(Name="/test/key")
print(response["Parameter"]["Value"])  # Output: test_value

cleanup_mock()  # Only applicable for 'temporary' mode
```

> Note: All supported services (SSM, S3, CodeArtifact, etc.) follow the same `boto3`-like client interface. You can call
> methods directly on the client instance, and the behavior will be local or delegated based on region configuration.

## Future Plans

- Extend to additional AWS services such as:
    - DynamoDB, S3, Lambda, CloudWatch, etc.
- Improved IAM user/role matching and permission enforcement.
- Enhanced logging, auditing, and multi-account support.
- Full AWS API coverage for supported services.
- Support for Config, CloudTrail, and authentication workflows.
- Multi-part S3 upload/download and versioning support.

## License

[MIT License](LICENSE)