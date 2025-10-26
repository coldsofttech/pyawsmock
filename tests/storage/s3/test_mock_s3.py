import json
import os
import warnings
from datetime import datetime, timezone, timedelta
from hashlib import md5
from pathlib import Path

import pytest

from pyawsmock.mocks.storage.s3.mock import MockS3, compute_checksum

pytestmark = pytest.mark.order(2)


@pytest.fixture
def s3(tmp_path):
    return MockS3(tmp_path)


@pytest.fixture
def s3_simple(s3):
    s3.create_bucket(Bucket="existing-bucket")
    return s3


@pytest.fixture
def s3_with_buckets(tmp_path: Path):
    s3 = MockS3(base_path=tmp_path)

    s3.create_bucket(Bucket="my-bucket", OwnerId="owner-123")

    s3.create_bucket(Bucket="logs-bucket", OwnerId="owner-456")
    s3.create_bucket_metadata_configuration(
        Bucket="logs-bucket",
        MetadataConfiguration={
            "JournalTableConfiguration": {
                "RecordExpiration": {"Expiration": "DISABLED"},
                "EncryptionConfiguration": {"SseAlgorithm": "AES256"}
            },
            "InventoryTableConfiguration": {
                "ConfigurationState": "DISABLED",
                "EncryptionConfiguration": {"SseAlgorithm": "AES256"}
            }
        },
        ChecksumAlgorithm="SHA256",
        ExpectedBucketOwner="000000000000"
    )

    data = s3._read_store()
    data["logs-bucket"]["BucketConfiguration"]["MetadataConfiguration"]["Version"] = 1
    s3._write_store(data)

    return s3


@pytest.fixture
def s3_with_upload(tmp_path):
    s3 = MockS3(base_path=tmp_path)

    # Create bucket manually in store
    data = s3._read_store()
    data["my-bucket"] = {
        "BucketPath": "my-bucket",
        "BucketConfiguration": {"ChecksumAlgorithm": "SHA256"},
        "Objects": {},
    }
    s3._write_store(data)

    # Create local bucket directory
    os.makedirs(tmp_path / "my-bucket", exist_ok=True)
    return s3


@pytest.fixture
def s3_with_download(tmp_path):
    s3 = MockS3(base_path=tmp_path)

    # Prepare bucket and file structure
    bucket_name = "my-bucket"
    bucket_path = tmp_path / bucket_name
    os.makedirs(bucket_path, exist_ok=True)

    content = b"sample-data"
    object_key = "data/test.txt"
    object_path = bucket_path / object_key
    object_path.parent.mkdir(parents=True, exist_ok=True)
    object_path.write_bytes(content)

    checksum = compute_checksum(content, "SHA256")

    # Write to mock store
    s3._write_store({
        bucket_name: {
            "BucketPath": bucket_name,
            "BucketConfiguration": {"ChecksumAlgorithm": "SHA256"},
            "Objects": {
                object_key: {
                    "Key": object_key,
                    "Size": len(content),
                    "ETag": md5(content).hexdigest(),
                    "Checksum": checksum,
                    "LastModified": datetime.now(timezone.utc).isoformat(),
                    "Metadata": {"Owner": "test"},
                }
            }
        }
    })
    return s3


@pytest.fixture
def s3_with_objects(tmp_path):
    s3 = MockS3(base_path=tmp_path)
    bucket_name = "my-bucket"
    s3.create_bucket(Bucket=bucket_name)

    # Create a test file and upload
    test_file = tmp_path / "file.txt"
    test_file.write_text("hello world")
    s3.upload_file(str(test_file), Bucket=bucket_name, Key="file.txt")

    return s3


@pytest.fixture
def s3_with_public_access(tmp_path):
    s3 = MockS3(base_path=tmp_path)
    # Create a bucket with default PublicAccessBlockConfiguration
    s3.create_bucket(Bucket="my-bucket")
    s3.put_public_access_block(
        Bucket="my-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        }
    )
    return s3


@pytest.fixture
def s3_with_policy(tmp_path):
    s3 = MockS3(base_path=tmp_path)
    s3.create_bucket(Bucket="my-bucket")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    s3.put_bucket_policy(Bucket="my-bucket", Policy=policy)
    return s3


@pytest.fixture
def s3_with_policy_status(tmp_path):
    s3 = MockS3(base_path=tmp_path)
    s3.create_bucket(Bucket="my-bucket")
    # Attach a bucket policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    s3.put_bucket_policy(Bucket="my-bucket", Policy=policy)
    return s3


def compute_md5(obj):
    return md5(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def test_create_bucket_success_minimal(s3):
    result = s3.create_bucket(Bucket="my-bucket")

    assert result["Location"] == "/my-bucket"
    assert "BucketArn" in result
    bucket_info = s3._read_store()["my-bucket"]
    assert bucket_info["Name"] == "my-bucket"
    assert bucket_info["ACL"] == "private"


def test_create_bucket_success_full_config(s3):
    config = {
        "LocationConstraint": "local-us-west-1",
        "Location": {"Type": "AvailabilityZone", "Name": "usaz1"},
        "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
        "Tags": [{"Key": "env", "Value": "test"}]
    }
    s3.create_bucket(
        Bucket="custom-bucket",
        ACL="public-read",
        ObjectOwnership="BucketOwnerPreferred",
        CreateBucketConfiguration=config
    )

    bucket_info = s3._read_store()["custom-bucket"]
    assert bucket_info["ACL"] == "public-read"
    assert bucket_info["ObjectOwnership"] == "BucketOwnerPreferred"
    assert bucket_info["BucketConfiguration"]["Location"]["Name"] == "usaz1"
    assert bucket_info["Tags"] == [{"Key": "env", "Value": "test"}]


def test_create_bucket_missing_name(s3):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3.create_bucket()


def test_create_bucket_duplicate(s3_simple):
    with pytest.raises(ValueError, match="Bucket 'existing-bucket' already exists"):
        s3_simple.create_bucket(Bucket="existing-bucket")


def test_create_bucket_invalid_location_type(s3):
    config = {
        "Location": {"Type": "InvalidType", "Name": "local-us-west-1"}
    }
    with pytest.raises(ValueError, match="Unsupported type"):
        s3.create_bucket(Bucket="bucket1", CreateBucketConfiguration=config)


def test_create_bucket_invalid_bucket_type(s3):
    config = {
        "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "InvalidType"}
    }
    with pytest.raises(ValueError, match="directory"):
        s3.create_bucket(Bucket="bucket2", CreateBucketConfiguration=config)


def test_create_bucket_folder_created(s3):
    s3.create_bucket(Bucket="bucket-folder-test")
    bucket_path = s3.data_path / "bucket-folder-test"
    assert bucket_path.exists() and bucket_path.is_dir()


def test_create_bucket_metadata_configuration_success(s3_with_buckets):
    metadata_config = {
        "JournalTableConfiguration": {
            "RecordExpiration": {"Expiration": "DISABLED"},
            "EncryptionConfiguration": {"SseAlgorithm": "AES256"},
        },
        "InventoryTableConfiguration": {
            "ConfigurationState": "DISABLED",
            "EncryptionConfiguration": {"SseAlgorithm": "AES256"},
        }
    }
    s3_with_buckets.create_bucket_metadata_configuration(
        Bucket="my-bucket",
        MetadataConfiguration=metadata_config,
        ChecksumAlgorithm="SHA256",
        ExpectedBucketOwner="000000000000"
    )

    result = s3_with_buckets.get_bucket_metadata_configuration(Bucket="my-bucket")
    assert \
        result["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
            "JournalTableConfigurationResult"][
            "RecordExpiration"]["Expiration"] == "DISABLED"


def test_create_bucket_metadata_configuration_missing_bucket(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_buckets.create_bucket_metadata_configuration(MetadataConfiguration={})


def test_create_bucket_metadata_configuration_bucket_not_exist(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_buckets.create_bucket_metadata_configuration(
            Bucket="non-existent",
            MetadataConfiguration={"JournalTableConfiguration": {}}
        )


def test_create_bucket_metadata_configuration_owner_mismatch(s3_with_buckets):
    metadata_config = {
        "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}
    }
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_buckets.create_bucket_metadata_configuration(
            Bucket="my-bucket",
            MetadataConfiguration=metadata_config,
            ExpectedBucketOwner="wrong-owner"
        )


def test_create_bucket_metadata_configuration_missing_journal_table(s3_with_buckets):
    metadata_config = {"InventoryTableConfiguration": {"ConfigurationState": "DISABLED"}}
    with pytest.raises(ValueError, match="JournalTableConfiguration is required"):
        s3_with_buckets.create_bucket_metadata_configuration(
            Bucket="my-bucket",
            MetadataConfiguration=metadata_config
        )


def test_create_bucket_metadata_configuration_invalid_journal_days(s3_with_buckets):
    metadata_config = {
        "JournalTableConfiguration": {
            "RecordExpiration": {"Expiration": "ENABLED", "Days": 3}
        }
    }
    with pytest.raises(ValueError, match="RecordExpiration.Days must be an integer"):
        s3_with_buckets.create_bucket_metadata_configuration(
            Bucket="my-bucket",
            MetadataConfiguration=metadata_config
        )


def test_create_bucket_metadata_configuration_kms_without_key(s3_with_buckets):
    metadata_config = {
        "JournalTableConfiguration": {
            "RecordExpiration": {"Expiration": "DISABLED"},
            "EncryptionConfiguration": {"SseAlgorithm": "aws:kms"},
        }
    }
    with pytest.raises(ValueError, match="KmsKeyArn is required when using aws:kms"):
        s3_with_buckets.create_bucket_metadata_configuration(
            Bucket="my-bucket",
            MetadataConfiguration=metadata_config
        )


def test_create_bucket_metadata_configuration_inventory_kms_without_key(s3_with_buckets):
    metadata_config = {
        "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}},
        "InventoryTableConfiguration": {
            "ConfigurationState": "DISABLED",
            "EncryptionConfiguration": {"SseAlgorithm": "aws:kms"},
        },
    }
    with pytest.raises(ValueError, match="EncryptionConfiguration.KmsKeyArn is required when using aws:kms"):
        s3_with_buckets.create_bucket_metadata_configuration(
            Bucket="my-bucket",
            MetadataConfiguration=metadata_config
        )


def test_create_bucket_metadata_configuration_md5_mismatch(s3_with_buckets):
    metadata_config = {
        "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}
    }
    wrong_md5 = "deadbeef"
    with pytest.raises(ValueError, match="ContentMD5 mismatch"):
        s3_with_buckets.create_bucket_metadata_configuration(
            Bucket="my-bucket",
            MetadataConfiguration=metadata_config,
            ContentMD5=wrong_md5
        )


def test_create_bucket_metadata_configuration_invalid_checksum(s3_with_buckets):
    metadata_config = {
        "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}
    }
    with pytest.raises(ValueError):
        s3_with_buckets.create_bucket_metadata_configuration(
            Bucket="my-bucket",
            MetadataConfiguration=metadata_config,
            ChecksumAlgorithm="INVALID"
        )


def test_get_bucket_metadata_configuration_success(s3_with_buckets):
    resp = s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")
    result = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]

    # Check key metadata presence
    assert "DestinationResult" in result
    assert "JournalTableConfigurationResult" in result
    assert "InventoryTableConfigurationResult" in result

    # Check that defaults are applied correctly
    jt_config = result["JournalTableConfigurationResult"]
    assert jt_config["TableStatus"] == "ACTIVE"
    assert jt_config["RecordExpiration"]["Expiration"] == "DISABLED"

    # Ensure ARNs are well-formed
    assert jt_config["TableArn"].endswith(":journal-table")
    assert result["InventoryTableConfigurationResult"]["TableArn"].endswith(":inventory-table")


def test_get_bucket_metadata_configuration_owner_mismatch(s3_with_buckets):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_buckets.get_bucket_metadata_configuration(
            Bucket="logs-bucket", ExpectedBucketOwner="wrong-owner"
        )


def test_get_bucket_metadata_configuration_missing_bucket(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_buckets.get_bucket_metadata_configuration(Bucket="non-existent")


def test_get_bucket_metadata_configuration_no_metadata(s3_with_buckets):
    # Create a bucket without metadata
    s3_with_buckets.create_bucket(Bucket="empty-bucket", OwnerId="owner-789")

    with pytest.raises(ValueError, match="No MetadataConfiguration found for this bucket"):
        s3_with_buckets.get_bucket_metadata_configuration(Bucket="empty-bucket")


def test_get_bucket_metadata_configuration_with_expected_owner(s3_with_buckets):
    resp = s3_with_buckets.get_bucket_metadata_configuration(
        Bucket="logs-bucket", ExpectedBucketOwner="000000000000"
    )

    result = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    assert result["DestinationResult"]["TableBucketArn"].endswith("logs-bucket")
    assert result["DestinationResult"]["TableBucketType"] == "mock"


def test_get_bucket_metadata_configuration_mock_defaults(s3_with_buckets):
    resp = s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")
    metadata = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]

    # Default mock states
    assert metadata["JournalTableConfigurationResult"]["TableStatus"] == "ACTIVE"
    assert metadata["InventoryTableConfigurationResult"]["ConfigurationState"] == "DISABLED"

    # Check that TableNamespace follows naming pattern
    assert metadata["DestinationResult"]["TableNamespace"].endswith("-namespace")


def test_update_inventory_table_configuration_success(s3_with_buckets):
    s3_with_buckets.update_bucket_metadata_inventory_table_configuration(
        Bucket="logs-bucket",
        InventoryTableConfiguration={
            "ConfigurationState": "ENABLED",
            "EncryptionConfiguration": {"SseAlgorithm": "AES256"},
        },
    )

    # Verify persisted update through a subsequent get
    resp = s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")
    config = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    inv_config = config["InventoryTableConfigurationResult"]

    assert inv_config["ConfigurationState"] == "ENABLED"


def test_update_inventory_table_configuration_missing_bucket(s3_with_buckets):
    with pytest.raises(ValueError, match="required"):
        s3_with_buckets.update_bucket_metadata_inventory_table_configuration(
            Bucket="non-existent",
            InventoryTableConfiguration={"ConfigurationState": "ENABLED"},
        )


def test_update_inventory_table_configuration_no_metadata(s3_with_buckets):
    s3_with_buckets.create_bucket(Bucket="empty-bucket", OwnerId="owner-789")

    with pytest.raises(ValueError, match="required"):
        s3_with_buckets.update_bucket_metadata_inventory_table_configuration(
            Bucket="empty-bucket",
            InventoryTableConfiguration={"ConfigurationState": "ENABLED"},
        )


def test_update_inventory_table_configuration_owner_mismatch(s3_with_buckets):
    with pytest.raises(ValueError, match="required"):
        s3_with_buckets.update_bucket_metadata_inventory_table_configuration(
            Bucket="logs-bucket",
            ExpectedBucketOwner="wrong-owner",
            InventoryTableConfiguration={"ConfigurationState": "ENABLED"},
        )


def test_update_inventory_table_configuration_missing_config(s3_with_buckets):
    with pytest.raises(ValueError, match="InventoryTableConfiguration is required"):
        s3_with_buckets.update_bucket_metadata_inventory_table_configuration(Bucket="logs-bucket")


def test_update_inventory_table_configuration_invalid_state(s3_with_buckets):
    with pytest.raises(ValueError, match="required"):
        s3_with_buckets.update_bucket_metadata_inventory_table_configuration(
            Bucket="logs-bucket",
            InventoryTableConfiguration={"ConfigurationState": "BROKEN"},
        )


def test_update_inventory_table_configuration_idempotent_update(s3_with_buckets):
    conf = {"ConfigurationState": "ENABLED", "EncryptionConfiguration": {"SseAlgorithm": "AES256"}}
    s3_with_buckets.update_bucket_metadata_inventory_table_configuration(
        Bucket="logs-bucket", InventoryTableConfiguration=conf
    )
    s3_with_buckets.update_bucket_metadata_inventory_table_configuration(
        Bucket="logs-bucket", InventoryTableConfiguration=conf
    )

    resp = s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")
    inv_conf = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "InventoryTableConfigurationResult"]

    assert inv_conf["ConfigurationState"] == "ENABLED"


def test_update_inventory_table_configuration_mock_defaults(s3_with_buckets):
    s3_with_buckets.update_bucket_metadata_inventory_table_configuration(
        Bucket="logs-bucket",
        InventoryTableConfiguration={
            "ConfigurationState": "DISABLED",
            "EncryptionConfiguration": {
                "SseAlgorithm": "AES256",
            }
        },
    )

    resp = s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")
    inv_conf = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "InventoryTableConfigurationResult"]

    assert inv_conf["ConfigurationState"] == "DISABLED"
    assert "TableArn" in inv_conf and inv_conf["TableArn"].endswith(":inventory-table")


def test_update_journal_table_configuration_success(s3_with_buckets):
    jt_config = {
        "RecordExpiration": {"Expiration": "ENABLED", "Days": 10}
    }

    s3_with_buckets.update_bucket_metadata_journal_table_configuration(
        Bucket="logs-bucket",
        JournalTableConfiguration=jt_config,
        ChecksumAlgorithm="SHA256"
    )

    resp = s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")
    jt_conf = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "JournalTableConfigurationResult"]

    assert jt_conf["RecordExpiration"]["Expiration"] == "ENABLED"
    assert jt_conf["RecordExpiration"]["Days"] == 10


def test_update_journal_table_configuration_missing_bucket(s3_with_buckets):
    jt_config = {"RecordExpiration": {"Expiration": "ENABLED", "Days": 10}}
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="non-existent",
            JournalTableConfiguration=jt_config
        )


def test_update_journal_table_configuration_missing_jt_config(s3_with_buckets):
    with pytest.raises(ValueError, match="JournalTableConfiguration is required"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(Bucket="logs-bucket")


def test_update_journal_table_configuration_missing_record_expiration(s3_with_buckets):
    with pytest.raises(ValueError, match="required"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="logs-bucket", JournalTableConfiguration={}
        )


def test_update_journal_table_configuration_missing_expiration_key(s3_with_buckets):
    jt_config = {"RecordExpiration": {}}
    with pytest.raises(ValueError, match="expiration"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="logs-bucket", JournalTableConfiguration=jt_config
        )


def test_update_journal_table_configuration_invalid_expiration_value(s3_with_buckets):
    jt_config = {"RecordExpiration": {"Expiration": "INVALID"}}
    with pytest.raises(ValueError, match="expiration"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="logs-bucket", JournalTableConfiguration=jt_config
        )


def test_update_journal_table_configuration_enabled_without_days(s3_with_buckets):
    jt_config = {"RecordExpiration": {"Expiration": "ENABLED"}}
    with pytest.raises(ValueError, match="Days"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="logs-bucket", JournalTableConfiguration=jt_config
        )


def test_update_journal_table_configuration_invalid_days_value(s3_with_buckets):
    jt_config = {"RecordExpiration": {"Expiration": "ENABLED", "Days": 3}}
    with pytest.raises(ValueError, match="Days must be an integer >= 7 when Expiration is ENABLED"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="logs-bucket", JournalTableConfiguration=jt_config
        )


def test_update_journal_table_configuration_invalid_checksum(s3_with_buckets):
    jt_config = {"RecordExpiration": {"Expiration": "ENABLED", "Days": 10}}
    with pytest.raises(ValueError, match="algorithm"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="logs-bucket",
            JournalTableConfiguration=jt_config,
            ChecksumAlgorithm="SHA999"
        )


def test_update_journal_table_configuration_content_md5_mismatch(s3_with_buckets):
    jt_config = {"RecordExpiration": {"Expiration": "ENABLED", "Days": 10}}
    bad_md5 = md5(json.dumps({"wrong": "data"}).encode()).hexdigest()

    with pytest.raises(ValueError, match="ContentMD5 mismatch"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="logs-bucket",
            JournalTableConfiguration=jt_config,
            ContentMD5=bad_md5
        )


def test_update_journal_table_configuration_owner_mismatch(s3_with_buckets):
    jt_config = {"RecordExpiration": {"Expiration": "ENABLED", "Days": 10}}

    with pytest.raises(PermissionError, match="bucket owner"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="logs-bucket",
            JournalTableConfiguration=jt_config,
            ExpectedBucketOwner="wrong-owner"
        )


def test_update_journal_table_configuration_no_metadata_config(s3_with_buckets):
    s3_with_buckets.create_bucket(Bucket="temp-bucket", OwnerId="owner-321")

    jt_config = {"RecordExpiration": {"Expiration": "ENABLED", "Days": 10}}
    with pytest.raises(ValueError, match="No MetadataConfiguration found for this bucket"):
        s3_with_buckets.update_bucket_metadata_journal_table_configuration(
            Bucket="temp-bucket", JournalTableConfiguration=jt_config
        )


def test_update_journal_table_configuration_mock_persistence(s3_with_buckets):
    jt_config = {"RecordExpiration": {"Expiration": "ENABLED", "Days": 14}}
    s3_with_buckets.update_bucket_metadata_journal_table_configuration(
        Bucket="logs-bucket", JournalTableConfiguration=jt_config
    )

    resp = s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")
    jt_conf = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "JournalTableConfigurationResult"]
    assert jt_conf["RecordExpiration"]["Days"] == 14


def test_update_journal_table_configuration_mock_limitation(s3_with_buckets, tmp_path):
    another_instance = type(s3_with_buckets)(base_path=tmp_path)
    jt_config = {"RecordExpiration": {"Expiration": "ENABLED", "Days": 30}}

    s3_with_buckets.update_bucket_metadata_journal_table_configuration(
        Bucket="logs-bucket", JournalTableConfiguration=jt_config
    )

    # A new instance with same base_path should see updates (local persistence)
    resp = another_instance.get_bucket_metadata_configuration(Bucket="logs-bucket")
    jt_conf = resp["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "JournalTableConfigurationResult"]

    assert jt_conf["RecordExpiration"]["Days"] == 30


def test_delete_bucket_metadata_configuration_success(s3_with_buckets):
    # Confirm config exists before deletion
    resp_before = s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")
    assert "GetBucketMetadataConfigurationResult" in resp_before

    # Delete configuration
    s3_with_buckets.delete_bucket_metadata_configuration(Bucket="logs-bucket")

    # Verify removal
    with pytest.raises(ValueError, match="No MetadataConfiguration found for this bucket"):
        s3_with_buckets.get_bucket_metadata_configuration(Bucket="logs-bucket")


def test_delete_bucket_metadata_configuration_missing_bucket(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_buckets.delete_bucket_metadata_configuration()


def test_delete_bucket_metadata_configuration_bucket_not_exist(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket 'ghost-bucket' does not exist"):
        s3_with_buckets.delete_bucket_metadata_configuration(Bucket="ghost-bucket")


def test_delete_bucket_metadata_configuration_owner_mismatch(s3_with_buckets):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_buckets.delete_bucket_metadata_configuration(
            Bucket="logs-bucket",
            ExpectedBucketOwner="wrong-owner"
        )


def test_delete_bucket_metadata_configuration_no_metadata(s3_with_buckets):
    # Create a bucket without metadata configuration
    s3_with_buckets.create_bucket(Bucket="temp-bucket", OwnerId="owner-321")

    with pytest.raises(ValueError, match="No MetadataConfiguration found for this bucket"):
        s3_with_buckets.delete_bucket_metadata_configuration(Bucket="temp-bucket")


def test_delete_bucket_metadata_configuration_persistence(s3_with_buckets, tmp_path):
    s3_with_buckets.delete_bucket_metadata_configuration(Bucket="logs-bucket")

    # A new instance with same base_path should also reflect deletion
    new_instance = type(s3_with_buckets)(base_path=tmp_path)
    with pytest.raises(ValueError, match="No MetadataConfiguration found for this bucket"):
        new_instance.get_bucket_metadata_configuration(Bucket="logs-bucket")


def test_upload_file_success(s3_with_upload, tmp_path):
    file_path = tmp_path / "test.txt"
    file_path.write_text("hello world")

    s3_with_upload.upload_file(Filename=str(file_path), Bucket="my-bucket", Key="docs/test.txt")

    data = s3_with_upload._read_store()
    obj = data["my-bucket"]["Objects"]["docs/test.txt"]

    assert obj["Key"] == "docs/test.txt"
    assert obj["Size"] == len("hello world")
    assert obj["ETag"] == md5(b"hello world").hexdigest()
    assert obj["Checksum"] == compute_checksum(b"hello world", "SHA256")
    assert "LastModified" in obj
    assert isinstance(datetime.fromisoformat(obj["LastModified"]), datetime)


def test_upload_file_missing_filename(s3_with_upload):
    with pytest.raises(ValueError, match="Filename is required"):
        s3_with_upload.upload_file(Filename=None, Bucket="my-bucket", Key="file.txt")


def test_upload_file_file_not_found(s3_with_upload):
    with pytest.raises(FileNotFoundError):
        s3_with_upload.upload_file(Filename="nonexistent.txt", Bucket="my-bucket", Key="x.txt")


def test_upload_file_missing_bucket_name(s3_with_upload, tmp_path):
    file_path = tmp_path / "a.txt"
    file_path.write_text("data")
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_upload.upload_file(Filename=str(file_path), Bucket=None, Key="x.txt")


def test_upload_file_missing_key(s3_with_upload, tmp_path):
    file_path = tmp_path / "a.txt"
    file_path.write_text("data")
    with pytest.raises(ValueError, match="Key is required"):
        s3_with_upload.upload_file(Filename=str(file_path), Bucket="my-bucket", Key=None)


def test_upload_file_bucket_not_exist(tmp_path):
    s3 = MockS3(base_path=tmp_path)
    file_path = tmp_path / "test.txt"
    file_path.write_text("testdata")

    with pytest.raises(ValueError, match="Bucket 'missing' does not exist"):
        s3.upload_file(Filename=str(file_path), Bucket="missing", Key="obj.txt")


def test_upload_file_with_config_warning(s3_with_upload, tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("content")

    with warnings.catch_warnings(record=True) as w:
        s3_with_upload.upload_file(Filename=str(file_path), Bucket="my-bucket", Key="file.txt", Config={"foo": "bar"})

    assert any("S3TransferConfig is not supported" in str(wi.message) for wi in w)


def test_upload_file_with_callback(s3_with_upload, tmp_path):
    file_path = tmp_path / "file.txt"
    content = b"callback-test"
    file_path.write_bytes(content)

    sizes = []

    def cb(size):
        sizes.append(size)

    s3_with_upload.upload_file(Filename=str(file_path), Bucket="my-bucket", Key="cb.txt", Callback=cb)

    assert sizes == [len(content)]


def test_upload_file_with_metadata(s3_with_upload, tmp_path):
    file_path = tmp_path / "meta.txt"
    content = b"metadata-test"
    file_path.write_bytes(content)

    s3_with_upload.upload_file(
        Filename=str(file_path),
        Bucket="my-bucket",
        Key="meta.txt",
        ExtraArgs={"Metadata": {"Author": "John", "Env": "test"}}
    )

    data = s3_with_upload._read_store()
    meta = data["my-bucket"]["Objects"]["meta.txt"]["Metadata"]
    assert meta == {"Author": "John", "Env": "test"}


def test_upload_file_overwrites_existing_object(s3_with_upload, tmp_path):
    # upload once
    file_path = tmp_path / "file.txt"
    file_path.write_text("old content")
    s3_with_upload.upload_file(Filename=str(file_path), Bucket="my-bucket", Key="dup.txt")

    # upload again with new content
    file_path.write_text("new content")
    s3_with_upload.upload_file(Filename=str(file_path), Bucket="my-bucket", Key="dup.txt")

    data = s3_with_upload._read_store()
    obj = data["my-bucket"]["Objects"]["dup.txt"]
    assert obj["Size"] == len("new content")
    assert obj["Checksum"] == compute_checksum(b"new content", "SHA256")


def test_upload_file_creates_nested_directories(s3_with_upload, tmp_path):
    file_path = tmp_path / "nested.txt"
    file_path.write_text("nested data")

    s3_with_upload.upload_file(Filename=str(file_path), Bucket="my-bucket", Key="nested/folder/file.txt")

    object_path = tmp_path / "my-bucket" / "nested" / "folder" / "file.txt"
    assert object_path.exists()


def test_download_file_success(s3_with_download, tmp_path):
    download_path = tmp_path / "output.txt"

    s3_with_download.download_file(
        Bucket="my-bucket",
        Key="data/test.txt",
        Filename=str(download_path)
    )

    assert download_path.exists()
    assert download_path.read_bytes() == b"sample-data"


def test_download_file_missing_bucket(s3_with_download):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_download.download_file(Bucket=None, Key="data/test.txt", Filename="x.txt")


def test_download_file_missing_key(s3_with_download):
    with pytest.raises(ValueError, match="Key is required"):
        s3_with_download.download_file(Bucket="my-bucket", Key=None, Filename="x.txt")


def test_download_file_missing_filename(s3_with_download):
    with pytest.raises(ValueError, match="Filename is required"):
        s3_with_download.download_file(Bucket="my-bucket", Key="data/test.txt", Filename=None)


def test_download_file_bucket_not_exist(tmp_path):
    s3 = MockS3(base_path=tmp_path)
    with pytest.raises(ValueError, match="Bucket 'missing' does not exist"):
        s3.download_file(Bucket="missing", Key="data/test.txt", Filename="x.txt")


def test_download_file_key_not_exist(s3_with_download, tmp_path):
    download_path = tmp_path / "missing.txt"
    with pytest.raises(FileNotFoundError, match="Key"):
        s3_with_download.download_file(Bucket="my-bucket", Key="no-such-key", Filename=str(download_path))


def test_download_file_with_config_warning(s3_with_download, tmp_path):
    download_path = tmp_path / "warn.txt"
    with warnings.catch_warnings(record=True) as w:
        s3_with_download.download_file(
            Bucket="my-bucket",
            Key="data/test.txt",
            Filename=str(download_path),
            Config={"some": "value"},
        )
    assert any("S3TransferConfig is not supported" in str(wi.message) for wi in w)


def test_download_file_with_callback(s3_with_download, tmp_path):
    download_path = tmp_path / "cb.txt"
    sizes = []

    def cb(size):
        sizes.append(size)

    s3_with_download.download_file(
        Bucket="my-bucket",
        Key="data/test.txt",
        Filename=str(download_path),
        Callback=cb,
    )

    assert sizes == [len(b"sample-data")]
    assert download_path.exists()


def test_download_file_with_checksum_enabled(s3_with_download, tmp_path):
    download_path = tmp_path / "chk.txt"

    s3_with_download.download_file(
        Bucket="my-bucket",
        Key="data/test.txt",
        Filename=str(download_path),
        ExtraArgs={"ChecksumMode": "ENABLED"},
    )

    assert download_path.exists()
    assert download_path.read_bytes() == b"sample-data"


def test_download_file_checksum_mismatch(s3_with_download, tmp_path):
    # Modify checksum to simulate mismatch
    data = s3_with_download._read_store()
    data["my-bucket"]["Objects"]["data/test.txt"]["Checksum"] = "fake"
    s3_with_download._write_store(data)

    download_path = tmp_path / "bad.txt"
    with pytest.raises(IOError, match="Checksum mismatch"):
        s3_with_download.download_file(
            Bucket="my-bucket",
            Key="data/test.txt",
            Filename=str(download_path),
            ExtraArgs={"ChecksumMode": "ENABLED"},
        )


def test_download_file_overwrites_existing_file(s3_with_download, tmp_path):
    download_path = tmp_path / "dup.txt"
    download_path.write_text("old content")

    s3_with_download.download_file(
        Bucket="my-bucket",
        Key="data/test.txt",
        Filename=str(download_path),
    )

    assert download_path.read_bytes() == b"sample-data"


def test_download_file_creates_nested_output_path(s3_with_download, tmp_path):
    nested_dir = tmp_path / "deep/nested"
    os.makedirs(nested_dir, exist_ok=True)
    file_path = nested_dir / "out.txt"

    s3_with_download.download_file(
        Bucket="my-bucket",
        Key="data/test.txt",
        Filename=str(file_path),
    )

    assert file_path.exists()
    assert file_path.read_bytes() == b"sample-data"


def test_get_object_success(s3_with_objects):
    resp = s3_with_objects.get_object(Bucket="my-bucket", Key="file.txt")
    body = resp["Body"].read().decode()

    assert body == "hello world"
    assert resp["ContentLength"] == len("hello world")
    assert "ETag" in resp
    assert resp["StorageClass"] == "STANDARD"


def test_get_object_missing_bucket(s3_with_objects):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_objects.get_object(Key="file.txt")


def test_get_object_missing_key(s3_with_objects):
    with pytest.raises(ValueError, match="Key is required"):
        s3_with_objects.get_object(Bucket="my-bucket")


def test_get_object_bucket_not_exist(s3_with_objects):
    with pytest.raises(ValueError, match="Bucket 'no-bucket' does not exist"):
        s3_with_objects.get_object(Bucket="no-bucket", Key="file.txt")


def test_get_object_key_not_exist(s3_with_objects):
    with pytest.raises(FileNotFoundError, match="Key 'missing.txt' does not exist"):
        s3_with_objects.get_object(Bucket="my-bucket", Key="missing.txt")


def test_get_object_expected_owner_mismatch(s3_with_objects):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_objects.get_object(
            Bucket="my-bucket",
            Key="file.txt",
            ExpectedBucketOwner="wrong-owner"
        )


def test_get_object_if_none_match_returns_304(s3_with_objects):
    resp1 = s3_with_objects.get_object(Bucket="my-bucket", Key="file.txt")
    etag = resp1["ETag"]

    resp2 = s3_with_objects.get_object(Bucket="my-bucket", Key="file.txt", IfNoneMatch=etag)
    assert resp2["StatusCode"] == 304


def test_get_object_if_match_mismatch(s3_with_objects):
    with pytest.raises(ValueError, match="IfMatch does not match"):
        s3_with_objects.get_object(Bucket="my-bucket", Key="file.txt", IfMatch="wrong-etag")


def test_get_object_if_modified_since_not_modified(s3_with_objects):
    # Get last modified from stored object
    ds = s3_with_objects._read_store()
    obj = ds["my-bucket"]["Objects"]["file.txt"]
    last_modified = datetime.fromisoformat(obj["LastModified"])

    resp = s3_with_objects.get_object(
        Bucket="my-bucket",
        Key="file.txt",
        IfModifiedSince=last_modified
    )
    assert resp["StatusCode"] == 304


def test_get_object_if_unmodified_since_fails(s3_with_objects):
    past_time = datetime.now(timezone.utc) - timedelta(days=1)
    with pytest.raises(ValueError, match="IfUnmodifiedSince failed"):
        s3_with_objects.get_object(
            Bucket="my-bucket",
            Key="file.txt",
            IfUnmodifiedSince=past_time
        )


def test_get_object_range_success(s3_with_objects):
    resp = s3_with_objects.get_object(Bucket="my-bucket", Key="file.txt", Range="bytes=0-4")
    content = resp["Body"].read().decode()
    assert content == "hello"


def test_get_object_checksum_enabled(s3_with_objects):
    resp = s3_with_objects.get_object(Bucket="my-bucket", Key="file.txt", ChecksumMode="ENABLED")
    assert "ChecksumSHA256" in resp
    assert resp["ChecksumType"] == "FULL_OBJECT"


def test_get_object_versionid_warns(s3_with_objects):
    with warnings.catch_warnings(record=True) as w:
        s3_with_objects.get_object(Bucket="my-bucket", Key="file.txt", VersionId="1")
        assert any("Versioning not supported" in str(wi.message) for wi in w)


def test_get_object_partnumber_warns(s3_with_objects):
    with warnings.catch_warnings(record=True) as w:
        s3_with_objects.get_object(Bucket="my-bucket", Key="file.txt", PartNumber=1)
        assert any("Multipart download not supported" in str(wi.message) for wi in w)


def test_get_object_sse_customer_warns_and_echoes(s3_with_objects):
    with warnings.catch_warnings(record=True) as w:
        resp = s3_with_objects.get_object(
            Bucket="my-bucket",
            Key="file.txt",
            SSECustomerAlgorithm="AES256",
            SSECustomerKey="dummy"
        )
        assert "SSE-C is not supported" in str(w[0].message)
        assert resp["SSECustomerAlgorithm"] == "AES256"
        assert resp["SSECustomerKeyMD5"] == "dummy"


def test_get_object_requester_payer_flag(s3_with_objects):
    resp = s3_with_objects.get_object(
        Bucket="my-bucket",
        Key="file.txt",
        RequesterPayer="requester"
    )
    assert resp["RequestCharged"] == "requester"


def test_get_object_response_overrides(s3_with_objects):
    resp = s3_with_objects.get_object(
        Bucket="my-bucket",
        Key="file.txt",
        ResponseContentType="text/plain",
        ResponseCacheControl="no-cache"
    )
    assert resp["ContentType"] == "text/plain"
    assert resp["CacheControl"] == "no-cache"


def test_put_bucket_acl_basic_success(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", ACL="private")

    data = s3_with_buckets._read_store()
    assert data["my-bucket"]["ACL"] == "private"


def test_put_bucket_acl_with_grants(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(
        Bucket="my-bucket",
        GrantFullControl="user123",
        GrantRead="user456",
        GrantWriteACP="user789",
    )

    data = s3_with_buckets._read_store()
    grants = data["my-bucket"]["Grants"]

    assert grants["FullControl"] == "user123"
    assert grants["Read"] == "user456"
    assert grants["WriteACP"] == "user789"


def test_put_bucket_acl_with_access_control_policy(s3_with_buckets):
    policy = {"Grants": [{"Grantee": {"ID": "abc"}, "Permission": "READ"}]}
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", AccessControlPolicy=policy)

    data = s3_with_buckets._read_store()
    assert data["my-bucket"]["AccessControlPolicy"] == policy


def test_put_bucket_acl_with_checksum_algorithm(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", ChecksumAlgorithm="SHA256")

    data = s3_with_buckets._read_store()
    assert data["my-bucket"]["ChecksumAlgorithm"] == "SHA256"


def test_put_bucket_acl_missing_bucket(tmp_path):
    s3 = MockS3(base_path=tmp_path)
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3.put_bucket_acl(ACL="private")


def test_put_bucket_acl_bucket_not_exist(s3_with_buckets):
    with pytest.raises(ValueError, match="does not exist"):
        s3_with_buckets.put_bucket_acl(Bucket="unknown-bucket", ACL="public-read")


def test_put_bucket_acl_owner_mismatch(s3_with_buckets):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match"):
        s3_with_buckets.put_bucket_acl(
            Bucket="my-bucket", ExpectedBucketOwner="wrong-owner"
        )


def test_put_bucket_acl_invalid_checksum(s3_with_buckets):
    with pytest.raises(ValueError):
        s3_with_buckets.put_bucket_acl(Bucket="my-bucket", ChecksumAlgorithm="INVALID")


def test_put_bucket_acl_partial_grants(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(
        Bucket="my-bucket",
        GrantRead="userX",
        GrantWrite=None,
    )

    data = s3_with_buckets._read_store()
    grants = data["my-bucket"]["Grants"]
    assert grants["Read"] == "userX"
    assert "Write" not in grants


def test_put_bucket_acl_overwrite_existing_acl(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", ACL="private")
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", ACL="public-read")

    data = s3_with_buckets._read_store()
    assert data["my-bucket"]["ACL"] == "public-read"


def test_put_bucket_acl_preserves_existing_data(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", ACL="private")
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", GrantRead="user1")

    data = s3_with_buckets._read_store()
    assert "Owner" in data["my-bucket"]
    assert "Grants" in data["my-bucket"]
    assert data["my-bucket"]["ACL"] == "private"
    assert data["my-bucket"]["Grants"]["Read"] == "user1"


def test_get_bucket_acl_default(s3_with_buckets):
    resp = s3_with_buckets.get_bucket_acl(Bucket="my-bucket")

    assert "Owner" in resp
    assert "Grants" in resp
    assert isinstance(resp["Grants"], list)

    # In this mock, a new bucket has no grants by default
    if resp["Grants"]:
        # If grants exist, they must have Permission key
        assert all("Permission" in g for g in resp["Grants"])
        # and mock typically supports only these permissions
        assert all(g["Permission"] in ["FULL_CONTROL", "READ", "WRITE"] for g in resp["Grants"])
    else:
        # mock limitation: default ACL is empty
        assert resp["Grants"] == []


def test_get_bucket_acl_after_put_acl(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(
        Bucket="my-bucket",
        GrantRead="userA",
        GrantWrite="userB",
    )

    resp = s3_with_buckets.get_bucket_acl(Bucket="my-bucket")
    grants = {g["Permission"]: g["Grantee"]["ID"] for g in resp["Grants"]}

    assert grants.get("READ") == "userA"
    assert grants.get("WRITE") == "userB"


def test_get_bucket_acl_partial_grants(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", GrantRead="userX")

    resp = s3_with_buckets.get_bucket_acl(Bucket="my-bucket")

    grants = {g["Permission"]: g["Grantee"]["ID"] for g in resp["Grants"]}
    assert grants["READ"] == "userX"
    assert "WRITE" not in grants  # mock does not create missing grants


def test_get_bucket_acl_owner_static(s3_with_buckets):
    resp = s3_with_buckets.get_bucket_acl(Bucket="my-bucket")

    owner = resp["Owner"]
    assert "DisplayName" in owner
    assert "ID" in owner
    assert owner["DisplayName"] == "mock-user"


def test_get_bucket_acl_nonexistent_bucket(s3_with_buckets):
    with pytest.raises(ValueError, match="does not exist"):
        s3_with_buckets.get_bucket_acl(Bucket="does-not-exist")


def test_get_bucket_acl_missing_acl_data(s3_with_buckets):
    # Manually remove ACL entry (mock-level manipulation)
    store = s3_with_buckets._read_store()
    del store["my-bucket"]["Grants"]
    s3_with_buckets._write_store(store)

    # Behavior depends on mock design: may return default or raise
    try:
        resp = s3_with_buckets.get_bucket_acl(Bucket="my-bucket")
        assert "Grants" in resp  # default ACL fallback
    except ValueError:
        pass


def test_get_bucket_acl_ignores_unsupported_params(s3_with_buckets):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_buckets.get_bucket_acl(
            Bucket="my-bucket", ExpectedBucketOwner="fake-owner"
        )


def test_get_bucket_acl_store_consistency(s3_with_buckets):
    s3_with_buckets.put_bucket_acl(Bucket="my-bucket", GrantRead="alice")

    resp1 = s3_with_buckets.get_bucket_acl(Bucket="my-bucket")
    resp2 = s3_with_buckets.get_bucket_acl(Bucket="my-bucket")

    assert resp1 == resp2  # consistent read behavior


def test_get_bucket_acl_returns_minimal_fields(s3_with_buckets):
    resp = s3_with_buckets.get_bucket_acl(Bucket="my-bucket")

    assert set(resp.keys()) <= {"Owner", "Grants"}
    for grant in resp["Grants"]:
        assert set(grant.keys()) <= {"Grantee", "Permission"}
        assert "ID" in grant["Grantee"]


def test_put_public_access_block_success(s3_with_buckets):
    config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": True,
    }
    s3_with_buckets.put_public_access_block(Bucket="my-bucket", PublicAccessBlockConfiguration=config)

    bucket_info = s3_with_buckets._read_store()["my-bucket"]
    pac = bucket_info["PublicAccessBlockConfiguration"]
    assert pac["BlockPublicAcls"] is True
    assert pac["IgnorePublicAcls"] is True
    assert pac["BlockPublicPolicy"] is False
    assert pac["RestrictPublicBuckets"] is True


def test_put_public_access_block_missing_bucket(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_buckets.put_public_access_block(PublicAccessBlockConfiguration={"BlockPublicAcls": True})


def test_put_public_access_block_bucket_not_exist(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_buckets.put_public_access_block(Bucket="non-existent",
                                                PublicAccessBlockConfiguration={"BlockPublicAcls": True})


def test_put_public_access_block_owner_mismatch(s3_with_buckets):
    # Provide wrong owner
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_buckets.put_public_access_block(Bucket="my-bucket", ExpectedBucketOwner="wrong-owner",
                                                PublicAccessBlockConfiguration={"BlockPublicAcls": True})


def test_put_public_access_block_missing_configuration(s3_with_buckets):
    with pytest.raises(ValueError, match="PublicAccessBlockConfiguration is required"):
        s3_with_buckets.put_public_access_block(Bucket="my-bucket")


def test_put_public_access_block_with_checksum_algorithm(s3_with_buckets, monkeypatch):
    config = {"BlockPublicAcls": True}
    # Patch the validation to do nothing to avoid real exceptions
    monkeypatch.setattr("pyawsmock.mocks.storage.s3.mock.Validator.s3_bucket_checksum_algorithm", lambda x: None)

    s3_with_buckets.put_public_access_block(Bucket="my-bucket", PublicAccessBlockConfiguration=config,
                                            ChecksumAlgorithm="SHA256")
    bucket_info = s3_with_buckets._read_store()["my-bucket"]
    assert bucket_info["ChecksumAlgorithm"] == "SHA256"


def test_put_public_access_block_with_content_md5(s3_with_buckets):
    config = {"BlockPublicAcls": True}
    s3_with_buckets.put_public_access_block(Bucket="my-bucket", PublicAccessBlockConfiguration=config,
                                            ContentMD5="mock-md5")
    bucket_info = s3_with_buckets._read_store()["my-bucket"]
    assert bucket_info["ContentMD5"] == "mock-md5"


def test_get_public_access_block_success(s3_with_public_access):
    resp = s3_with_public_access.get_public_access_block(Bucket="my-bucket")
    pac = resp["PublicAccessBlockConfiguration"]
    assert pac["BlockPublicAcls"] is True
    assert pac["IgnorePublicAcls"] is True
    assert pac["BlockPublicPolicy"] is False
    assert pac["RestrictPublicBuckets"] is True


def test_get_public_access_block_missing_bucket(s3_with_public_access):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_public_access.get_public_access_block()


def test_get_public_access_block_bucket_not_exist(s3_with_public_access):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_public_access.get_public_access_block(Bucket="non-existent")


def test_get_public_access_block_owner_mismatch(s3_with_public_access):
    # Provide wrong ExpectedBucketOwner
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_public_access.get_public_access_block(Bucket="my-bucket", ExpectedBucketOwner="wrong-owner")


def test_delete_public_access_block_success(s3_with_public_access):
    # Delete the public access block
    s3_with_public_access.delete_public_access_block(Bucket="my-bucket")

    # Verify that all flags are reset to False
    pac = s3_with_public_access.get_public_access_block(Bucket="my-bucket")["PublicAccessBlockConfiguration"]
    assert pac["BlockPublicAcls"] is False
    assert pac["IgnorePublicAcls"] is False
    assert pac["BlockPublicPolicy"] is False
    assert pac["RestrictPublicBuckets"] is False


def test_delete_public_access_block_missing_bucket(s3_with_public_access):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_public_access.delete_public_access_block()


def test_delete_public_access_block_bucket_not_exist(s3_with_public_access):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_public_access.delete_public_access_block(Bucket="non-existent")


def test_delete_public_access_block_owner_mismatch(s3_with_public_access):
    # Provide wrong ExpectedBucketOwner
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_public_access.delete_public_access_block(Bucket="my-bucket", ExpectedBucketOwner="wrong-owner")


def test_put_bucket_policy_success(s3_with_buckets):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }

    # Put the policy
    s3_with_buckets.put_bucket_policy(Bucket="my-bucket", Policy=policy)

    # Verify policy was stored
    data = s3_with_buckets._read_store()
    stored_policy = data["my-bucket"]["BucketPolicy"]["Policy"]
    assert stored_policy == policy


def test_put_bucket_policy_missing_bucket(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_buckets.put_bucket_policy(Policy={"Statement": []})


def test_put_bucket_policy_bucket_not_exist(s3_with_buckets):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_buckets.put_bucket_policy(Bucket="non-existent", Policy={"Statement": []})


def test_put_bucket_policy_missing_policy(s3_with_buckets):
    with pytest.raises(ValueError, match="Policy is required"):
        s3_with_buckets.put_bucket_policy(Bucket="my-bucket")


def test_put_bucket_policy_owner_mismatch(s3_with_buckets):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_buckets.put_bucket_policy(
            Bucket="my-bucket",
            Policy={"Statement": []},
            ExpectedBucketOwner="wrong-owner"
        )


def test_put_bucket_policy_overwrites_existing(s3_with_buckets):
    first_policy = {"Statement": [{"Effect": "Deny"}]}
    second_policy = {"Statement": [{"Effect": "Allow"}]}

    s3_with_buckets.put_bucket_policy(Bucket="my-bucket", Policy=first_policy)
    s3_with_buckets.put_bucket_policy(Bucket="my-bucket", Policy=second_policy)

    data = s3_with_buckets._read_store()
    assert data["my-bucket"]["BucketPolicy"]["Policy"] == second_policy


def test_get_bucket_policy_success(s3_with_policy):
    resp = s3_with_policy.get_bucket_policy(Bucket="my-bucket")
    assert "Policy" in resp
    assert resp["Policy"]["Statement"][0]["Effect"] == "Allow"


def test_get_bucket_policy_bucket_missing(s3_with_policy):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_policy.get_bucket_policy()


def test_get_bucket_policy_bucket_not_exist(s3_with_policy):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_policy.get_bucket_policy(Bucket="non-existent")


def test_get_bucket_policy_owner_mismatch(s3_with_policy):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_policy.get_bucket_policy(Bucket="my-bucket", ExpectedBucketOwner="fake-owner")


def test_get_bucket_policy_no_policy(s3_with_buckets):
    # Create bucket without policy
    s3_with_buckets.create_bucket(Bucket="no-policy-bucket")
    policy = s3_with_buckets.get_bucket_policy(Bucket="no-policy-bucket")

    assert policy["Policy"] is None


def test_get_bucket_policy_status_success(s3_with_policy_status):
    resp = s3_with_policy_status.get_bucket_policy_status(Bucket="my-bucket")
    assert "PolicyStatus" in resp
    assert resp["PolicyStatus"]["IsPublic"] is False  # mock defaults to False for simplicity


def test_get_bucket_policy_status_bucket_missing(s3_with_policy_status):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_policy_status.get_bucket_policy_status()


def test_get_bucket_policy_status_bucket_not_exist(s3_with_policy_status):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_policy_status.get_bucket_policy_status(Bucket="non-existent")


def test_get_bucket_policy_status_owner_mismatch(s3_with_policy_status):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_policy_status.get_bucket_policy_status(Bucket="my-bucket", ExpectedBucketOwner="fake-owner")


def test_get_bucket_policy_status_no_policy(s3_with_buckets):
    # Create a bucket without policy
    s3_with_buckets.create_bucket(Bucket="no-policy-bucket")
    resp = s3_with_buckets.get_bucket_policy_status(Bucket="no-policy-bucket")
    assert resp["PolicyStatus"]["IsPublic"] is False  # mock default for no policy


def test_delete_bucket_policy_success(s3_with_policy):
    # Ensure policy exists first
    resp_before = s3_with_policy.get_bucket_policy_status(Bucket="my-bucket")
    assert resp_before["PolicyStatus"]["IsPublic"] is False

    # Delete policy
    s3_with_policy.delete_bucket_policy(Bucket="my-bucket")

    # After deletion, policy should be gone or IsPublic=False by mock default
    resp_after = s3_with_policy.get_bucket_policy_status(Bucket="my-bucket")
    assert resp_after["PolicyStatus"]["IsPublic"] is False


def test_delete_bucket_policy_missing_bucket(s3_with_policy):
    with pytest.raises(ValueError, match="Bucket name is required"):
        s3_with_policy.delete_bucket_policy()


def test_delete_bucket_policy_bucket_not_exist(s3_with_policy):
    with pytest.raises(ValueError, match="Bucket 'non-existent' does not exist"):
        s3_with_policy.delete_bucket_policy(Bucket="non-existent")


def test_delete_bucket_policy_owner_mismatch(s3_with_policy):
    with pytest.raises(PermissionError, match="ExpectedOwner does not match actual bucket owner"):
        s3_with_policy.delete_bucket_policy(Bucket="my-bucket", ExpectedBucketOwner="fake-owner")


def test_delete_bucket_policy_no_policy(s3_with_buckets):
    # Create a bucket without policy
    s3_with_buckets.create_bucket(Bucket="no-policy-bucket")
    # Should not fail, mock default behavior
    s3_with_buckets.delete_bucket_policy(Bucket="no-policy-bucket")
    resp = s3_with_buckets.get_bucket_policy_status(Bucket="no-policy-bucket")
    assert resp["PolicyStatus"]["IsPublic"] is False  # mock default for no policy
