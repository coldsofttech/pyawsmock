import gzip
import json
import os
import re
import warnings
import zlib
from datetime import datetime, timezone
from hashlib import md5, sha1, sha256
from typing import Dict, Any

from pyawsmock.mocks.base_mock import MockBase


def validate_s3_bucket_acl(acl: str):
    if acl.lower() not in ["private", "public-read", "public-read-write", "authenticated-read"]:
        raise ValueError(
            "Unsupported ACL. Supported ACLs are private, public-read, public-read-write, and authenticated-read."
        )


def validate_s3_bucket_region(region: str):
    from pyawsmock.mocks.base_mock import validate_region
    if not validate_region(region):
        raise ValueError("Unsupported region. Supported regions: local-*")


def validate_s3_bucket_location_type(type_: str):
    if type_ not in ["AvailabilityZone", "LocalZone"]:
        raise ValueError("Unsupported type. Supported types: AvailabilityZone, LocalZone")


def validate_s3_bucket_object_ownership(ownership: str):
    if ownership not in ["BucketOwnerPreferred", "ObjectWriter", "BucketOwnerEnforced"]:
        raise ValueError(
            "Unsupported ownership. Supported are BucketOwnerPreferred, ObjectWriter, and BucketOwnerEnforced."
        )


def validate_s3_bucket_data_redundancy(redundancy: str):
    if redundancy not in ["SingleAvailabilityZone", "SingleLocalZone"]:
        raise ValueError("Unsupported redundancy. Supported are SingleAvailabilityZone, SingleLocalZone")


def validate_s3_bucket_journal_table_record_expiration(expiry: str):
    if expiry not in ["ENABLED", "DISABLED"]:
        raise ValueError("Unsupported expiration. Supported expirations: ENABLED, DISABLED")


def validate_s3_bucket_sse_algorithm(alog: str):
    if alog not in ["aws:kms", "AES256"]:
        raise ValueError("Unsupported algorithm. Supported algorithms: aws:kms, AES256")


def validate_s3_bucket_inventory_table_state(state: str):
    if state not in ["ENABLED", "DISABLED"]:
        raise ValueError("Unsupported state. Supported states: ENABLED, DISABLED")


def validate_s3_bucket_checksum_algorithm(alog: str):
    if alog not in ["CRC32", "CRC32C", "SHA1", "SHA256", "CRC64NVME"]:
        raise ValueError("Unsupported algorithm. Supported algorithms: CRC32, CRC32C, SHA1, SHA256, CRC64NVME")


def validate_tags(tags):
    if tags is None:
        return

    if not isinstance(tags, list):
        raise ValueError("Tags must be a list of dictionaries")

    seen_keys = set()
    tag_pattern = re.compile(r"^[\w\s_.:/=+\-@]+$")

    for tag in tags:
        if not isinstance(tag, dict):
            raise ValueError(f"Invalid tag type: {type(tag)}. Expected a dictionary.")

        key = tag.get("Key")
        value = tag.get("Value")

        if key is None or value is None:
            raise ValueError("Each tag must contain 'Key' and 'Value'")

        if not isinstance(key, str):
            raise ValueError(f"Tag Key must be a string: {key}")
        if len(key) == 0 or len(key) > 128:
            raise ValueError(f"Tag Key must be between 1 and 128 characters: {key}")
        if not tag_pattern.match(key):
            raise ValueError(f"Tag Key contains invalid characters: {key}")
        if key in seen_keys:
            raise ValueError(f"Duplicate Tag Key found: {key}")
        seen_keys.add(key)

        if not isinstance(value, str):
            raise ValueError(f"Tag Value must be a string for Key '{key}'")
        if len(value) > 256:
            raise ValueError(f"Tag Value exceeds 256 characters for Key '{key}'")
        if not tag_pattern.match(value) and value != "":
            raise ValueError(f"Tag Value contains invalid characters: {value}")


def compute_checksum(content: bytes, alog: str) -> str:
    alog = alog.upper()

    if alog == "MD5":
        return md5(content).hexdigest()
    elif alog == "SHA1":
        return sha1(content).hexdigest()
    elif alog == "SHA256":
        return sha256(content).hexdigest()
    elif alog == "CRC32":
        return format(zlib.crc32(content) & 0xFFFFFFFF, "08x")
    elif alog == "CRC32C":
        from crcmod import crcmod

        crc32c_func = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
        return format(crc32c_func(content) & 0xFFFFFFFF, "08x")
    elif alog == "CRC64NVME":
        from crcmod import crcmod

        crc64_func = crcmod.mkCrcFun(0x42F0E1EBA9EA3693, initCrc=0, rev=False, xorOut=0)
        return format(crc64_func(content) & 0xFFFFFFFFFFFFFFFF, "016x")
    else:
        raise ValueError(f"Unsupported checksum algorithm: {alog}")


class MockS3(MockBase):
    _supported_methods = [
        "create_bucket",
        "create_bucket_metadata_configuration",
        "get_bucket_metadata_configuration",
        "update_bucket_metadata_inventory_table_configuration",
        "update_bucket_metadata_journal_table_configuration",
        "delete_bucket_metadata_configuration",
        "upload_file",
        "download_file",
        "get_object",
    ]

    def __init__(self, base_path):
        self.base_path = base_path
        self.store_path = base_path / "s3_buckets.json"
        self.data_path = base_path / "global" / "S3"
        os.makedirs(self.data_path, exist_ok=True)
        self.lock_path = f"{self.store_path}.lock"
        os.makedirs(self.store_path.parent, exist_ok=True)
        if not self.store_path.exists():
            self._write_store({})

    def _read_store(self):
        try:
            with gzip.open(self.store_path, "rb") as f:
                return json.loads(f.read().decode("utf-8"))
        except FileNotFoundError:
            return {}

    def _write_store(self, data):
        from filelock import FileLock

        lock = FileLock(self.lock_path)
        with lock:
            with gzip.open(self.store_path, "wb") as f:
                f.write(json.dumps(data, indent=4).encode("utf-8"))

    def create_bucket(self, **kwargs) -> Dict[str, Any]:
        acl = kwargs.get("ACL", "private")
        bucket = kwargs.get("Bucket")
        create_bucket_config = kwargs.get("CreateBucketConfiguration", {})
        grant_full_control = kwargs.get("GrantFullControl")
        grant_read = kwargs.get("GrantRead")
        grant_read_acp = kwargs.get("GrantReadACP")
        grant_write = kwargs.get("GrantWrite")
        grant_write_acp = kwargs.get("GrantWriteACP")
        obj_lock_enabled_for_bucket = kwargs.get("ObjectLockEnabledForBucket", False)
        obj_ownership = kwargs.get("ObjectOwnership", "BucketOwnerEnforced")

        if not bucket:
            raise ValueError("Bucket name is required")

        data_store = self._read_store()
        if bucket in data_store:
            raise ValueError(f"Bucket '{bucket}' already exists")

        region = create_bucket_config.get("LocationConstraint", "local-us-east-1")

        validate_s3_bucket_acl(acl)
        validate_s3_bucket_region(region)
        validate_s3_bucket_object_ownership(obj_ownership)

        bucket_info = {
            "Name": bucket,
            "ACL": acl,
            "Grants": {
                "FullControl": grant_full_control,
                "Read": grant_read,
                "ReadACP": grant_read_acp,
                "Write": grant_write,
                "WriteACP": grant_write_acp,
            },
            "ObjectLockEnabledForBucket": obj_lock_enabled_for_bucket,
            "ObjectOwnership": obj_ownership,
            "Region": region,
            "BucketConfiguration": {},
            "VersioningConfiguration": {
                "Status": "Suspended",
            }
        }

        location = create_bucket_config.get("Location") if create_bucket_config else None
        if location:
            location_type = location.get("Type")
            location_name = location.get("Name")
            validate_s3_bucket_location_type(location_type)
            if not isinstance(location_name, str) or not location_name:
                raise ValueError("Location name must be a non-empty string")
            bucket_info["BucketConfiguration"]["Location"] = {
                "Type": location_type,
                "Name": location_name,
            }

        bucket_cfg = create_bucket_config.get("Bucket") if create_bucket_config else None
        if bucket_cfg:
            redundancy = bucket_cfg.get("DataRedundancy", "SingleAvailabilityZone")
            bucket_type = bucket_cfg.get("Type", "Directory")
            validate_s3_bucket_data_redundancy(redundancy)
            if bucket_type != "Directory":
                raise ValueError(f"Invalid bucket type: {bucket_type}")
            bucket_info["BucketConfiguration"]["Bucket"] = {
                "DataRedundancy": redundancy,
                "Type": bucket_type,
            }

        tags = create_bucket_config.get("Tags", [])
        if tags:
            validate_tags(tags)
            bucket_info["Tags"] = tags

        bucket_info["Arn"] = f"arn:mock:s3::000000000000:{bucket}"
        bucket_info["CreatedDate"] = datetime.now(timezone.utc).isoformat()
        bucket_info["Owner"] = {
            "ID": "000000000000",
            "DisplayName": "mock-user",
        }

        bucket_path = self.data_path / bucket
        os.makedirs(bucket_path, exist_ok=True)

        bucket_info["BucketPath"] = str(bucket_path.relative_to(self.base_path))

        data_store[bucket] = bucket_info
        self._write_store(data_store)

        return {
            "Location": f"/{bucket}",
            "BucketArn": bucket_info["Arn"],
            "ResponseMetadata": {
                "HTTPStatusCode": 200,
            },
        }

    def create_bucket_metadata_configuration(self, **kwargs):
        bucket = kwargs.get("Bucket")
        metadata_config = kwargs.get("MetadataConfiguration", {})
        content_md5 = kwargs.get("ContentMD5")
        checksum_alog = kwargs.get("ChecksumAlgorithm", "SHA256")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        if not bucket:
            raise ValueError("Bucket name is required")

        data_store = self._read_store()
        if bucket not in data_store:
            raise ValueError(f"Bucket '{bucket}' does not exist")

        actual_owner = data_store[bucket]["Owner"]["ID"]
        if expected_owner and expected_owner != actual_owner:
            raise PermissionError("ExpectedOwner does not match actual bucket owner")

        jt_config = metadata_config.get("JournalTableConfiguration")
        it_config = metadata_config.get("InventoryTableConfiguration")

        if not jt_config:
            raise ValueError("JournalTableConfiguration is required")

        rec = jt_config.get("RecordExpiration", {})
        rec_expiry = rec.get("Expiration")
        if rec_expiry:
            validate_s3_bucket_journal_table_record_expiration(rec_expiry)
        if rec_expiry == "ENABLED":
            days = rec.get("Days", 0)
            if not (isinstance(days, int) and 7 <= days <= 2147483647):
                raise ValueError(
                    "RecordExpiration.Days must be an integer between 7 and 2147483647"
                )

        enc = jt_config.get("EncryptionConfiguration", {})
        sse_alog = enc.get("SseAlgorithm")
        if sse_alog:
            validate_s3_bucket_sse_algorithm(sse_alog)
        if sse_alog == "aws:kms" and not enc.get("KmsKeyArn"):
            raise ValueError("KmsKeyArn is required when using aws:kms")

        if it_config:
            it_state = it_config.get("ConfigurationState")
            if it_state:
                validate_s3_bucket_inventory_table_state(it_state)
            ienc = it_config.get("EncryptionConfiguration", {})
            ienc_sse_alog = ienc.get("SseAlgorithm")
            if ienc_sse_alog:
                validate_s3_bucket_sse_algorithm(ienc_sse_alog)
            if ienc_sse_alog == "aws:kms" and not ienc.get("KmsKeyArn"):
                raise ValueError(
                    "EncryptionConfiguration.KmsKeyArn is required when using aws:kms"
                )

        computed_md5 = md5(json.dumps(metadata_config, sort_keys=True).encode()).hexdigest()
        if content_md5 and content_md5 != computed_md5:
            raise ValueError("ContentMD5 mismatch (mock validation)")

        if checksum_alog:
            validate_s3_bucket_checksum_algorithm(checksum_alog)

        bucket_info = data_store[bucket]
        bucket_info["BucketConfiguration"]["MetadataConfiguration"] = metadata_config
        bucket_info["BucketConfiguration"]["MetadataConfiguration"]["ChecksumAlgorithm"] = checksum_alog
        bucket_info["BucketConfiguration"]["MetadataConfiguration"]["ContentMD5"] = content_md5
        bucket_info["BucketConfiguration"]["MetadataConfiguration"]["ExpectedBucketOwner"] = expected_owner
        bucket_info["BucketConfiguration"]["MetadataConfiguration"]["ModifiedDate"] = datetime.now(
            timezone.utc).isoformat()

        data_store[bucket] = bucket_info
        self._write_store(data_store)

        return None

    def get_bucket_metadata_configuration(self, **kwargs) -> Dict[str, Any]:
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        data_store = self._read_store()
        if bucket not in data_store:
            raise ValueError(f"Bucket '{bucket}' does not exist")

        bucket = data_store[bucket]
        if expected_owner and expected_owner != bucket["Owner"]["ID"]:
            raise PermissionError("ExpectedOwner does not match actual bucket owner")

        metadata_config = bucket.get("BucketConfiguration", {}).get("MetadataConfiguration")
        if not metadata_config:
            raise ValueError("No MetadataConfiguration found for this bucket")

        bucket_arn = bucket["Arn"]
        jt_arn = f"{bucket_arn}:journal-table"
        it_arn = f"{bucket_arn}:inventory-table"

        return {
            "GetBucketMetadataConfigurationResult": {
                "MetadataConfigurationResult": {
                    "DestinationResult": {
                        "TableBucketType": "mock",  # mocked default
                        "TableBucketArn": bucket_arn,
                        "TableNamespace": f"{bucket['Name']}-namespace",
                    },
                    "JournalTableConfigurationResult": {
                        "TableStatus": "ACTIVE",  # mocked default
                        "Error": {},
                        "TableName": f"{bucket['Name']}-journal",
                        "TableArn": jt_arn,
                        "RecordExpiration": metadata_config.get("JournalTableConfiguration", {}).get("RecordExpiration",
                                                                                                     {}),
                    },
                    "InventoryTableConfigurationResult": {
                        "ConfigurationState": metadata_config.get("InventoryTableConfiguration", {}).get(
                            "ConfigurationState", "DISABLED"),
                        "TableStatus": "ACTIVE",  # mocked default
                        "Error": {},
                        "TableName": f"{bucket['Name']}-inventory",
                        "TableArn": it_arn,
                    }
                }
            }
        }

    def update_bucket_metadata_inventory_table_configuration(self, **kwargs):
        bucket = kwargs.get("Bucket")
        content_md5 = kwargs.get("ContentMD5")
        checksum_alog = kwargs.get("ChecksumAlgorithm", "SHA256")
        it_config = kwargs.get("InventoryTableConfiguration", {})
        expected_owner = kwargs.get("ExpectedBucketOwner")

        if not bucket:
            raise ValueError("Bucket name is required")
        if not it_config:
            raise ValueError("InventoryTableConfiguration is required")
        if "ConfigurationState" not in it_config:
            raise ValueError("ConfigurationState is required")
        if "EncryptionConfiguration" not in it_config:
            raise ValueError("EncryptionConfiguration is required")

        enc_config = it_config.get("EncryptionConfiguration")
        if "SseAlgorithm" not in enc_config:
            raise ValueError("SseAlgorithm is required")

        data_store = self._read_store()
        if bucket not in data_store:
            raise ValueError(f"Bucket '{bucket}' does not exist")

        bucket_info = data_store[bucket]
        if expected_owner and expected_owner != bucket_info["Owner"]["ID"]:
            raise PermissionError("ExpectedOwner does not match actual bucket owner")

        validate_s3_bucket_checksum_algorithm(checksum_alog)
        validate_s3_bucket_inventory_table_state(it_config["ConfigurationState"])
        validate_s3_bucket_sse_algorithm(enc_config["SseAlgorithm"])

        bucket_config = bucket_info.setdefault("BucketConfiguration", {})
        metadata_config = bucket_config.setdefault("MetadataConfiguration", {})

        if not metadata_config:
            raise ValueError("No MetadataConfiguration found for this bucket")

        if content_md5:
            computed_md5 = md5(json.dumps(it_config, sort_keys=True).encode()).hexdigest()
            if computed_md5 != content_md5:
                raise ValueError("ContentMD5 mismatch (mock validation)")

        metadata_config["ChecksumAlgorithm"] = checksum_alog
        metadata_config["InventoryTableConfiguration"] = {
            "ConfigurationState": it_config["ConfigurationState"],
            "EncryptionConfiguration": it_config["EncryptionConfiguration"],
        }
        metadata_config["ModifiedDate"] = datetime.now(timezone.utc).isoformat()
        data_store[bucket] = bucket_info
        self._write_store(data_store)

        return None

    def update_bucket_metadata_journal_table_configuration(self, **kwargs):
        bucket = kwargs.get("Bucket")
        content_md5 = kwargs.get("ContentMD5")
        checksum_alg = kwargs.get("ChecksumAlgorithm", "SHA256")
        jt_config = kwargs.get("JournalTableConfiguration", {})
        expected_owner = kwargs.get("ExpectedBucketOwner")

        if not bucket:
            raise ValueError("Bucket name is required")
        if not jt_config:
            raise ValueError("JournalTableConfiguration is required")
        if "RecordExpiration" not in jt_config:
            raise ValueError("RecordExpiration is required in JournalTableConfiguration")

        validate_s3_bucket_checksum_algorithm(checksum_alg)

        record_exp = jt_config.get("RecordExpiration")
        if "Expiration" not in record_exp:
            raise ValueError("Expiration is required in RecordExpiration")

        validate_s3_bucket_journal_table_record_expiration(record_exp["Expiration"])
        if record_exp["Expiration"] == "ENABLED":
            if "Days" not in record_exp:
                raise ValueError("Days must be specified when Expiration is ENABLED")
            if not isinstance(record_exp["Days"], int) or not (7 <= int(record_exp["Days"]) <= 2147483647):
                raise ValueError("Days must be an integer >= 7 when Expiration is ENABLED")

        data_store = self._read_store()
        if bucket not in data_store:
            raise ValueError(f"Bucket '{bucket}' does not exist")

        bucket_data = data_store[bucket]
        if expected_owner and expected_owner != bucket_data["Owner"]["ID"]:
            raise PermissionError("ExpectedBucketOwner does not match actual bucket owner")

        bucket_config = bucket_data.setdefault("BucketConfiguration", {})
        metadata_config = bucket_config.setdefault("MetadataConfiguration", {})
        if not metadata_config:
            raise ValueError("No MetadataConfiguration found for this bucket")

        if content_md5:
            computed_md5 = md5(json.dumps(jt_config, sort_keys=True).encode()).hexdigest()
            if computed_md5 != content_md5:
                raise ValueError("ContentMD5 mismatch (mock validation)")

        metadata_config["ChecksumAlgorithm"] = checksum_alg
        metadata_config["JournalTableConfiguration"] = {
            "RecordExpiration": record_exp
        }
        metadata_config["ModifiedDate"] = datetime.now(timezone.utc).isoformat()

        data_store[bucket] = bucket_data
        self._write_store(data_store)

        return None

    def delete_bucket_metadata_configuration(self, **kwargs):
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        if not bucket:
            raise ValueError("Bucket name is required")

        data_store = self._read_store()
        if bucket not in data_store:
            raise ValueError(f"Bucket '{bucket}' does not exist")

        bucket_info = data_store[bucket]
        if expected_owner and expected_owner != bucket_info["Owner"]["ID"]:
            raise PermissionError("ExpectedBucketOwner does not match actual bucket owner")

        bucket_config = bucket_info.get("BucketConfiguration", {})
        if "MetadataConfiguration" not in bucket_config:
            raise ValueError("No MetadataConfiguration found for this bucket")

        del bucket_config["MetadataConfiguration"]
        bucket_info["BucketConfiguration"] = bucket_config
        data_store[bucket] = bucket_info
        self._write_store(data_store)

        return None

    def upload_file(self, Filename, Bucket, Key, ExtraArgs=None, Callback=None, Config=None):
        if not Filename:
            raise ValueError("Filename is required")
        if not os.path.exists(Filename):
            raise FileNotFoundError(Filename)
        if not Bucket:
            raise ValueError("Bucket name is required")
        if not Key:
            raise ValueError("Key is required")

        data_store = self._read_store()
        if Bucket not in data_store:
            raise ValueError(f"Bucket '{Bucket}' does not exist")

        if Config:
            warnings.warn("S3TransferConfig is not supported in the mock.")

        bucket_info = data_store[Bucket]
        with open(Filename, "rb") as f:
            content = f.read()

        size = len(content)
        etag = md5(content).hexdigest()
        bucket_config = bucket_info.setdefault("BucketConfiguration", {})
        checksum_alog = bucket_config.get("ChecksumAlgorithm", "SHA256")
        checksum = compute_checksum(content, checksum_alog)
        if Callback:
            Callback(size)

        bucket_path = bucket_info["BucketPath"]
        object_path = os.path.join(self.base_path, bucket_path, Key)
        with open(object_path, "wb") as f:
            f.write(content)

        extra = ExtraArgs or {}
        metadata = extra.get("Metadata", {})
        objects = bucket_info.setdefault("Objects", {})
        objects[Key] = {
            "Key": Key,
            "Size": size,
            "ETag": etag,
            "Checksum": checksum,
            "LastModified": datetime.now(timezone.utc).isoformat(),
            "Metadata": metadata,
        }
        bucket_info["Objects"] = objects
        data_store[Bucket] = bucket_info
        self._write_store(data_store)

        return None

    def download_file(self, Bucket, Key, Filename, ExtraArgs=None, Callback=None, Config=None):
        if not Bucket:
            raise ValueError("Bucket name is required")
        if not Key:
            raise ValueError("Key is required")
        if not Filename:
            raise ValueError("Filename is required")

        data_store = self._read_store()
        if Bucket not in data_store:
            raise ValueError(f"Bucket '{Bucket}' does not exist")

        bucket_info = data_store[Bucket]
        objects = bucket_info.setdefault("Objects", {})
        if Key not in objects:
            raise FileNotFoundError(f"Key '{Key}' does not exist")

        if Config:
            warnings.warn("S3TransferConfig is not supported in the mock.")

        bucket_path = bucket_info["BucketPath"]
        object_path = os.path.join(self.base_path, bucket_path, Key)
        with open(object_path, "rb") as f:
            content = f.read()

        object_ = objects[Key]
        extra = ExtraArgs or {}
        checksum_mode = extra.get("ChecksumMode", "DISABLED")
        if checksum_mode == "ENABLED":
            stored_checksum = object_["Checksum"]
            content_checksum = compute_checksum(content,
                                                bucket_info.get("BucketConfiguration", {}).get("ChecksumAlgorithm",
                                                                                               "SHA256"))
            if stored_checksum != content_checksum:
                raise IOError("Checksum mismatch")

        with open(Filename, "wb") as f:
            f.write(content)

        if Callback:
            Callback(object_["Size"])

        return None

    def get_object(self, **kwargs) -> Dict[str, Any]:
        bucket = kwargs.get("Bucket")
        if_match = kwargs.get("IfMatch")
        if_modified_since = kwargs.get("IfModifiedSince")
        if_none_match = kwargs.get("IfNoneMatch")
        if_unmodified_since = kwargs.get("IfUnmodifiedSince")
        key = kwargs.get("Key")
        range_ = kwargs.get("Range")
        version_id = kwargs.get("VersionId")
        sse_cust_alog = kwargs.get("SSECustomerAlgorithm")
        sse_cust_key = kwargs.get("SSECustomerKey")
        req_payer = kwargs.get("RequesterPayer")
        part_number = kwargs.get("PartNumber")
        expected_owner = kwargs.get("ExpectedBucketOwner")
        checksum_mode = kwargs.get("ChecksumMode")

        if not bucket:
            raise ValueError("Bucket name is required")
        if not key:
            raise ValueError("Key is required")

        if version_id:
            warnings.warn("Versioning not supported in local mock")
        if part_number:
            warnings.warn("Multipart download not supported in local mock")

        data_store = self._read_store()
        if bucket not in data_store:
            raise ValueError(f"Bucket '{bucket}' does not exist")

        bucket_info = data_store[bucket]
        objects = bucket_info.setdefault("Objects", {})
        if key not in objects:
            raise FileNotFoundError(f"Key '{key}' does not exist")

        actual_owner = bucket_info["Owner"]["ID"]
        if expected_owner and expected_owner != actual_owner:
            raise PermissionError("ExpectedOwner does not match actual bucket owner")

        object_ = objects[key]
        bucket_path = bucket_info["BucketPath"]
        object_path = os.path.join(self.base_path, bucket_path, key)

        with open(object_path, "rb") as f:
            content = f.read()

        last_modified = datetime.fromisoformat(object_["LastModified"])

        if if_match and if_match != object_["ETag"]:
            raise ValueError("412 Precondition Failed: IfMatch does not match")
        if if_unmodified_since and last_modified > if_unmodified_since:
            raise ValueError("412 Precondition Failed: IfUnmodifiedSince failed")
        if if_none_match and if_none_match == object_["ETag"]:
            return {"StatusCode": 304}
        if if_modified_since and last_modified <= if_modified_since:
            return {"StatusCode": 304}

        if range_:
            if range_.startswith("bytes="):
                start_end = range_[len("bytes="):].split("-")
                start = int(start_end[0]) if start_end[0] else 0
                end = int(start_end[1]) + 1 if start_end[1] else len(content)
                content = content[start:end]

        checksums = {}
        if checksum_mode == "ENABLED":
            checksums["ChecksumCRC32"] = compute_checksum(content, "CRC32")
            checksums["ChecksumCRC32C"] = compute_checksum(content, "CRC32C")
            checksums["ChecksumCRC64NVME"] = compute_checksum(content, "CRC64NVME")
            checksums["ChecksumSHA1"] = compute_checksum(content, "SHA1")
            checksums["ChecksumSHA256"] = compute_checksum(content, "SHA256")
            checksums["ChecksumType"] = "FULL_OBJECT"

        from pyawsmock.mocks.storage.s3.streaming import MockStreamingBody
        response = {
            "Body": MockStreamingBody(content),
            "LastModified": last_modified,
            "ContentLength": len(content),
            "ETag": object_["ETag"],
            "Metadata": object_.get("Metadata", {}),
            "ServerSideEncryption": "AES256",  # default for mock
            "SSEKMSKeyId": None,  # default for mock
            "BucketKeyEnabled": False,  # default for mock
            "DeleteMarker": False,  # default for mock
            "AcceptRanges": "bytes",  # default for mock
            "Expiration": None,  # default for mock
            "Restore": None,  # default for mock
            "MissingMeta": 0,  # default for mock
            "VersionId": "1",  # default version
            "ExpiresString": None,  # default for mock
            "WebsiteRedirectLocation": None,  # default for mock
            "StorageClass": "STANDARD",  # default for mock
            "ReplicationStatus": None,  # default for mock
            "PartsCount": None,  # default for mock
            "TagCount": 0,  # default for mock
            "ObjectLockMode": None,  # default for mock
            "ObjectLockRetainUntilDate": None,  # default for mock
            "ObjectLockLegalHoldStatus": None,  # default for mock
            **checksums
        }

        if sse_cust_alog or sse_cust_key:
            warnings.warn("SSE-C is not supported in local mock, but fields will be echoed")
            response["SSECustomerAlgorithm"] = sse_cust_alog
            response["SSECustomerKeyMD5"] = sse_cust_key or None

        if req_payer == "requester":
            response["RequestCharged"] = "requester"

        response_headers_map = {
            "ResponseCacheControl": "CacheControl",
            "ResponseContentDisposition": "ContentDisposition",
            "ResponseContentEncoding": "ContentEncoding",
            "ResponseContentLanguage": "ContentLanguage",
            "ResponseContentType": "ContentType",
            "ResponseExpires": "Expires"
        }
        for arg_key, resp_key in response_headers_map.items():
            if arg_key in kwargs:
                response[resp_key] = kwargs[arg_key]

        return response
