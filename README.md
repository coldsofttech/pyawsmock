# Local AWS Mock - Python Package (`pyawsmock`)

A lightweight Python package that **mocks AWS services locally** for development and testing. Currently, supports **AWS
Systems Manager (SSM) Parameter Store**.

This package **extends boto3** and automatically delegates calls to real AWS when the region is not a local mock region.

## Key Features

- **Local vs AWS Delegation**
    - Regions starting with `local-*` use the **local mock store**.
    - Other regions delegate calls directory to `boto3` for real AWS services.
- **Persistent or Temporary Storage**
    - **Persistent Mode:** Provide a directory path to store the configurations for local mock across sessions.
    - **Temporary Mode:** Uses a temporary directory (`tempfile`) and supports `cleanup()` to remove temporary data.
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
- **Audit History**
    - Tracks the IAM user/role performing operations (currently defaults to `mock-user`).
    - Timestamps modifications for audit purposes.
- **ARNs & Account IDs**
    - Uses `arn:mock` instead of `arn:aws` to clearly differentiate local mock resources.
    - Default AWS Account ID is `000000000000` for all mock ARNs.

## Current Limitations

- **Unsupported AWS Features**
    - Config
    - CloudTrail
    - IAM (Users, Groups, Roles, Policies - permissions are not enforced)
    - Authentication
- **Default Assumptions**
    - All operations assume a single mock IAM user (`mock-user`).
    - Regions are either `local-*` for mock or real AWS regions for delegation.

> These limitations may be addressed in future versions.

## Supported Services (Current)

| Service               | Methods                                                                                                                                                                                                  |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SSM (Parameter Store) | `put_parameter`, `get_parameter`, `get_parameters`, `delete_parameter`, `label_parameter_version`, `unlabel_parameter_version`, `describe_parameters`, `get_parameters_by_path`, `get_parameter_history` |

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

## Future Plans

- Extend to additional AWS services such as:
    - DynamoDB, S3, Lambda, CloudWatch, etc.
- Improved IAM user/role matching and permission enforcement.
- Enhanced logging, auditing, and multi-account support.
- Full AWS API coverage for supported services.
- Support for Config, CloudTrail, and authentication workflows.

## License

[MIT License](LICENSE)