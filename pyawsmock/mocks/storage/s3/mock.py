import json
import os
import re
import warnings
import zlib
from datetime import datetime, timezone
from hashlib import md5, sha1, sha256
from typing import Dict, Any

from pyawsmock.mocks.base_mock import MockBase, validate_region
from pyawsmock.mocks.storage.s3.streaming import MockStreamingBody
from pyawsmock.mocks.store_utils import StoreUtils


class MockS3Validator:
    TAG_PATTERN = re.compile(r"^[\w\s_.:/=+\-@]+$")

    @staticmethod
    def _raise_if(condition, message):
        if condition:
            raise ValueError(message)

    @classmethod
    def s3_bucket_acl(cls, acl: str):
        cls._raise_if(
            acl.lower() not in ["private", "public-read", "public-read-write", "authenticated-read"],
            "Unsupported ACL. Supported ACLs are private, public-read, public-read-write, and authenticated-read."
        )

    @classmethod
    def s3_bucket_region(cls, region: str):
        cls._raise_if(
            not validate_region(region),
            "Unsupported region. Supported regions: local-*"
        )

    @classmethod
    def s3_bucket_location_name(cls, name: str):
        cls._raise_if(
            not isinstance(name, str) or not name,
            "LocationName must be a non-empty string."
        )

    @classmethod
    def s3_bucket_location_type(cls, type_: str):
        cls._raise_if(
            type_ not in ["AvailabilityZone", "LocalZone"],
            "Unsupported type. Supported types: AvailabilityZone, LocalZone"
        )

    @classmethod
    def s3_bucket_object_ownership(cls, ownership: str):
        cls._raise_if(
            ownership not in ["BucketOwnerPreferred", "ObjectWriter", "BucketOwnerEnforced"],
            "Unsupported ownership. Supported are BucketOwnerPreferred, ObjectWriter, and BucketOwnerEnforced."
        )

    @classmethod
    def s3_bucket_data_redundancy(cls, redundancy: str):
        cls._raise_if(
            redundancy not in ["SingleAvailabilityZone", "SingleLocalZone"],
            "Unsupported redundancy. Supported are SingleAvailabilityZone, SingleLocalZone"
        )

    @classmethod
    def s3_bucket_journal_table_record_expiration(cls, expiry: str):
        cls._raise_if(
            expiry not in ["ENABLED", "DISABLED"],
            "Unsupported expiration. Supported expirations: ENABLED, DISABLED"
        )

    @classmethod
    def s3_bucket_sse_algorithm(cls, alog: str):
        cls._raise_if(
            alog not in ["aws:kms", "AES256"],
            "Unsupported algorithm. Supported algorithms: aws:kms, AES256"
        )

    @classmethod
    def s3_bucket_inventory_table_state(cls, state: str):
        cls._raise_if(
            state not in ["ENABLED", "DISABLED"],
            "Unsupported state. Supported states: ENABLED, DISABLED"
        )

    @classmethod
    def s3_bucket_checksum_algorithm(cls, alog: str):
        cls._raise_if(
            alog not in ["CRC32", "CRC32C", "SHA1", "SHA256", "CRC64NVME"],
            "Unsupported algorithm. Supported algorithms: CRC32, CRC32C, SHA1, SHA256, CRC64NVME"
        )

    @classmethod
    def tags(cls, tags):
        if tags is None:
            return
        cls._raise_if(not isinstance(tags, list), "Tags must be a list of dictionaries")

        seen_keys = set()
        for tag in tags:
            cls._raise_if(not isinstance(tag, dict), f"Invalid tag type: {type(tag)}. Expected dict.")
            key, value = tag.get("Key"), tag.get("Value")
            cls._raise_if(key is None or value is None, "Each tag must contain 'Key' and 'Value'")
            cls._validate_tag_field("Key", key, 128, seen_keys)
            cls._validate_tag_field("Value", value, 256)

    @classmethod
    def _validate_tag_field(cls, field_name, value, max_len, seen_keys=None):
        cls._raise_if(not isinstance(value, str), f"Tag {field_name} must be a string")
        if field_name == "Key":
            cls._raise_if(value in seen_keys, f"Duplicate Tag Key found: {value}")
            seen_keys.add(value)
        cls._raise_if(not value and field_name == "Key", f"Tag {field_name} cannot be empty")
        cls._raise_if(len(value) > max_len, f"Tag {field_name} exceeds {max_len} characters")
        cls._raise_if(value != "" and not cls.TAG_PATTERN.match(value),
                      f"Tag {field_name} contains invalid characters: {value}")


Validator = MockS3Validator


def compute_checksum(content: bytes, alog: str) -> str:
    def fake_crc64(data: bytes):
        return sha1(data).hexdigest()[:16]

    alog = alog.upper()
    if alog == "MD5":
        return md5(content).hexdigest()
    if alog == "SHA1":
        return sha1(content).hexdigest()
    if alog == "SHA256":
        return sha256(content).hexdigest()
    if alog == "CRC32":
        return format(zlib.crc32(content) & 0xFFFFFFFF, "08x")
    if alog == "CRC32C":
        from crcmod import crcmod
        crc32c_func = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
        return format(crc32c_func(content) & 0xFFFFFFFF, "08x")
    if alog == "CRC64NVME":
        return fake_crc64(content)
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
        return StoreUtils.read_json_gzip(self.store_path)

    def _write_store(self, data):
        StoreUtils.write_json_gzip(self.store_path, data, self.lock_path)

    def _get_bucket_info(self, bucket: str, expected_owner: str = None) -> Any:
        if not bucket:
            raise ValueError("Bucket name is required")
        data_store = self._read_store()
        if bucket not in data_store:
            raise ValueError(f"Bucket '{bucket}' does not exist")
        bucket_info = data_store[bucket]
        if expected_owner and bucket_info["Owner"]["ID"] != expected_owner:
            raise PermissionError("ExpectedOwner does not match actual bucket owner")
        return bucket_info, data_store

    def _get_metadata_config(self, bucket_info: Dict[str, Any]) -> Dict[str, Any]:
        bucket_config = bucket_info.setdefault("BucketConfiguration", {})
        metadata_config = bucket_config.setdefault("MetadataConfiguration", {})
        if not metadata_config:
            raise ValueError("No MetadataConfiguration found for this bucket")
        return metadata_config

    def _validate_md5(self, obj: dict, content_md5: str):
        if content_md5:
            computed_md5 = md5(json.dumps(obj, sort_keys=True).encode()).hexdigest()
            if computed_md5 != content_md5:
                raise ValueError("ContentMD5 mismatch (mock validation)")

    def _update_metadata_modified_date(self, metadata_config: dict):
        metadata_config["ModifiedDate"] = datetime.now(timezone.utc).isoformat()

    def _validate_transfer_config(self, config):
        if config:
            warnings.warn("S3TransferConfig is not supported in the mock.")

    def _read_object_path(self, bucket_info, key):
        bucket_path = bucket_info["BucketPath"]
        return os.path.join(self.base_path, bucket_path, key)

    def _get_object_entry(self, bucket_info, key):
        objects = bucket_info.setdefault("Objects", {})
        if key not in objects:
            raise FileNotFoundError(f"Key '{key}' does not exist")
        return objects[key]

    def _evaluate_preconditions(self, object_, last_modified, kwargs):
        if_match = kwargs.get("IfMatch")
        if_none_match = kwargs.get("IfNoneMatch")
        if_modified_since = kwargs.get("IfModifiedSince")
        if_unmodified_since = kwargs.get("IfUnmodifiedSince")

        if if_match and if_match != object_["ETag"]:
            raise ValueError("412 Precondition Failed: IfMatch does not match")
        if if_unmodified_since and last_modified > if_unmodified_since:
            raise ValueError("412 Precondition Failed: IfUnmodifiedSince failed")
        if if_none_match and if_none_match == object_["ETag"]:
            return {"StatusCode": 304}
        if if_modified_since and last_modified <= if_modified_since:
            return {"StatusCode": 304}
        return None

    def _apply_range(self, content, range_):
        if not range_ or not range_.startswith("bytes="):
            return content
        start_end = range_[len("bytes="):].split("-")
        start = int(start_end[0]) if start_end[0] else 0
        end = int(start_end[1]) + 1 if start_end[1] else len(content)
        return content[start:end]

    def _compute_checksums_if_enabled(self, content, checksum_mode):
        if checksum_mode != "ENABLED":
            return {}
        return {
            "ChecksumCRC32": compute_checksum(content, "CRC32"),
            "ChecksumCRC32C": compute_checksum(content, "CRC32C"),
            "ChecksumCRC64NVME": compute_checksum(content, "CRC64NVME"),
            "ChecksumSHA1": compute_checksum(content, "SHA1"),
            "ChecksumSHA256": compute_checksum(content, "SHA256"),
            "ChecksumType": "FULL_OBJECT",
        }

    @staticmethod
    def compute_checksum(content: bytes, alog: str) -> str:
        return compute_checksum(content, alog)

    def create_bucket(self, **kwargs) -> Dict[str, Any]:
        acl = kwargs.get("ACL", "private")
        bucket = kwargs.get("Bucket")
        create_bucket_config = kwargs.get("CreateBucketConfiguration", {})
        obj_ownership = kwargs.get("ObjectOwnership", "BucketOwnerEnforced")

        if not bucket:
            raise ValueError("Bucket name is required")

        data_store = self._read_store()
        if bucket in data_store:
            raise ValueError(f"Bucket '{bucket}' already exists")

        region = create_bucket_config.get("LocationConstraint", "local-us-east-1")
        Validator.s3_bucket_acl(acl)
        Validator.s3_bucket_region(region)
        Validator.s3_bucket_object_ownership(obj_ownership)

        bucket_info = {
            "Name": bucket,
            "ACL": acl,
            "Grants": {},
            "ObjectLockEnabledForBucket": kwargs.get("ObjectLockEnabledForBucket", False),
            "ObjectOwnership": obj_ownership,
            "Region": region,
            "BucketConfiguration": {},
            "VersioningConfiguration": {"Status": "Suspended"},
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            },
            "Arn": f"arn:mock:s3::000000000000:{bucket}",
            "CreatedDate": datetime.now(timezone.utc).isoformat(),
            "Owner": {"ID": "000000000000", "DisplayName": "mock-user"},
        }

        if location := create_bucket_config.get("Location"):
            Validator.s3_bucket_location_name(location.get("Name"))
            Validator.s3_bucket_location_type(location.get("Type"))
            bucket_info["BucketConfiguration"]["Location"] = location

        if bucket_cfg := create_bucket_config.get("Bucket"):
            Validator.s3_bucket_data_redundancy(bucket_cfg.get("DataRedundancy", "SingleAvailabilityZone"))
            if bucket_cfg.get("Type", "Directory") != "Directory":
                raise ValueError(f"Bucket '{bucket_cfg.get('Name')}' is not a directory")
            bucket_info["BucketConfiguration"]["Bucket"] = bucket_cfg

        if tags := create_bucket_config.get("Tags"):
            Validator.tags(tags)
            bucket_info["Tags"] = tags

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
        checksum_alg = kwargs.get("ChecksumAlgorithm", "SHA256")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        jt_config = metadata_config.get("JournalTableConfiguration")
        if not jt_config:
            raise ValueError("JournalTableConfiguration is required")
        rec_exp = jt_config.get("RecordExpiration", {})
        if rec_exp.get("Expiration"):
            Validator.s3_bucket_journal_table_record_expiration(rec_exp.get("Expiration"))
            if rec_exp.get("Expiration") == "ENABLED":
                days = rec_exp.get("Days", 0)
                if not (isinstance(days, int) and 7 <= days <= 2147483647):
                    raise ValueError("RecordExpiration.Days must be an integer between 7 and 2147483647")
        sse_alg = jt_config.get("EncryptionConfiguration", {}).get("SseAlgorithm")
        if sse_alg:
            Validator.s3_bucket_sse_algorithm(sse_alg)
        if sse_alg == "aws:kms" and not jt_config.get("EncryptionConfiguration", {}).get("KmsKeyArn"):
            raise ValueError("KmsKeyArn is required when using aws:kms")

        it_config = metadata_config.get("InventoryTableConfiguration")
        if it_config:
            state = it_config.get("ConfigurationState")
            if state:
                Validator.s3_bucket_inventory_table_state(state)
            ienc_alg = it_config.get("EncryptionConfiguration", {}).get("SseAlgorithm")
            if ienc_alg:
                Validator.s3_bucket_sse_algorithm(ienc_alg)
            if ienc_alg == "aws:kms" and not it_config.get("EncryptionConfiguration", {}).get("KmsKeyArn"):
                raise ValueError("EncryptionConfiguration.KmsKeyArn is required when using aws:kms")

        self._validate_md5(metadata_config, content_md5)
        if checksum_alg:
            Validator.s3_bucket_checksum_algorithm(checksum_alg)

        bucket_info.setdefault("BucketConfiguration", {})["MetadataConfiguration"] = metadata_config
        md_conf = bucket_info["BucketConfiguration"]["MetadataConfiguration"]
        md_conf["ChecksumAlgorithm"] = checksum_alg
        md_conf["ContentMD5"] = content_md5
        md_conf["ExpectedBucketOwner"] = expected_owner
        self._update_metadata_modified_date(md_conf)

        data_store = self._read_store()
        data_store[bucket] = bucket_info
        self._write_store(data_store)

    def get_bucket_metadata_configuration(self, **kwargs) -> Dict[str, Any]:
        bucket_info, _ = self._get_bucket_info(kwargs.get("Bucket"), kwargs.get("ExpectedBucketOwner"))
        metadata_config = bucket_info.get("BucketConfiguration", {}).get("MetadataConfiguration")
        if not metadata_config:
            raise ValueError("No MetadataConfiguration found for this bucket")
        return {
            "GetBucketMetadataConfigurationResult": {
                "MetadataConfigurationResult": {
                    "DestinationResult": {
                        "TableBucketType": "mock",  # mocked default
                        "TableBucketArn": bucket_info["Arn"],
                        "TableNamespace": f"{bucket_info['Name']}-namespace",
                    },
                    "JournalTableConfigurationResult": {
                        "TableStatus": "ACTIVE",  # mocked default
                        "Error": {},
                        "TableName": f"{bucket_info['Name']}-journal",
                        "TableArn": f"{bucket_info['Arn']}:journal-table",
                        "RecordExpiration": metadata_config.get("JournalTableConfiguration", {}).get("RecordExpiration",
                                                                                                     {}),
                    },
                    "InventoryTableConfigurationResult": {
                        "ConfigurationState": metadata_config.get("InventoryTableConfiguration", {}).get(
                            "ConfigurationState", "DISABLED"),
                        "TableStatus": "ACTIVE",  # mocked default
                        "Error": {},
                        "TableName": f"{bucket_info['Name']}-inventory",
                        "TableArn": f"{bucket_info['Name']}:inventory-table",
                    }
                }
            }
        }

    def update_bucket_metadata_inventory_table_configuration(self, **kwargs):
        bucket = kwargs.get("Bucket")
        content_md5 = kwargs.get("ContentMD5")
        checksum_alg = kwargs.get("ChecksumAlgorithm", "SHA256")
        it_config = kwargs.get("InventoryTableConfiguration", {})
        expected_owner = kwargs.get("ExpectedBucketOwner")

        if not it_config:
            raise ValueError("InventoryTableConfiguration is required")

        enc_config = it_config.get("EncryptionConfiguration")
        if not enc_config or "SseAlgorithm" not in enc_config:
            raise ValueError("SseAlgorithm is required in EncryptionConfiguration")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        metadata_config = self._get_metadata_config(bucket_info)

        self._validate_md5(it_config, content_md5)
        Validator.s3_bucket_checksum_algorithm(checksum_alg)
        Validator.s3_bucket_inventory_table_state(it_config["ConfigurationState"])
        Validator.s3_bucket_sse_algorithm(enc_config["SseAlgorithm"])

        metadata_config["ChecksumAlgorithm"] = checksum_alg
        metadata_config["InventoryTableConfiguration"] = it_config
        self._update_metadata_modified_date(metadata_config)

        data_store = self._read_store()
        data_store[bucket] = bucket_info
        self._write_store(data_store)

    def update_bucket_metadata_journal_table_configuration(self, **kwargs):
        bucket = kwargs.get("Bucket")
        content_md5 = kwargs.get("ContentMD5")
        checksum_alg = kwargs.get("ChecksumAlgorithm", "SHA256")
        jt_config = kwargs.get("JournalTableConfiguration", {})
        expected_owner = kwargs.get("ExpectedBucketOwner")

        if not jt_config:
            raise ValueError("JournalTableConfiguration is required")
        if "RecordExpiration" not in jt_config:
            raise ValueError("RecordExpiration is required in JournalTableConfiguration")

        rec_exp = jt_config.get("RecordExpiration")
        Validator.s3_bucket_journal_table_record_expiration(rec_exp.get("Expiration"))
        if rec_exp.get("Expiration") == "ENABLED":
            days = rec_exp.get("Days")
            if not isinstance(days, int) or not (7 <= days <= 2147483647):
                raise ValueError("Days must be an integer >= 7 when Expiration is ENABLED")

        Validator.s3_bucket_checksum_algorithm(checksum_alg)
        self._validate_md5(jt_config, content_md5)

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        metadata_config = self._get_metadata_config(bucket_info)

        metadata_config["ChecksumAlgorithm"] = checksum_alg
        metadata_config["JournalTableConfiguration"] = jt_config
        self._update_metadata_modified_date(metadata_config)

        data_store = self._read_store()
        data_store[bucket] = bucket_info
        self._write_store(data_store)

    def delete_bucket_metadata_configuration(self, **kwargs):
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        bucket_config = bucket_info.get("BucketConfiguration", {})

        if "MetadataConfiguration" not in bucket_config:
            raise ValueError("No MetadataConfiguration found for this bucket")

        del bucket_config["MetadataConfiguration"]
        bucket_info["BucketConfiguration"] = bucket_config

        data_store = self._read_store()
        data_store[bucket] = bucket_info
        self._write_store(data_store)

    def upload_file(self, Filename, Bucket, Key, ExtraArgs=None, Callback=None, Config=None):
        if not Filename:
            raise ValueError("Filename is required")
        if not os.path.exists(Filename):
            raise FileNotFoundError(Filename)
        if not Bucket:
            raise ValueError("Bucket name is required")
        if not Key:
            raise ValueError("Key is required")

        bucket_info, data_store = self._get_bucket_info(Bucket)
        self._validate_transfer_config(Config)
        with open(Filename, "rb") as f:
            content = f.read()

        size = len(content)
        etag = md5(content).hexdigest()
        bucket_config = bucket_info.setdefault("BucketConfiguration", {})
        checksum_algo = bucket_config.get("ChecksumAlgorithm", "SHA256")
        checksum = compute_checksum(content, checksum_algo)

        if Callback:
            Callback(size)

        object_path = self._read_object_path(bucket_info, Key)
        os.makedirs(os.path.dirname(object_path), exist_ok=True)
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

        data_store[Bucket] = bucket_info
        self._write_store(data_store)

    def download_file(self, Bucket, Key, Filename, ExtraArgs=None, Callback=None, Config=None):
        if not Bucket:
            raise ValueError("Bucket name is required")
        if not Key:
            raise ValueError("Key is required")
        if not Filename:
            raise ValueError("Filename is required")

        bucket_info, data_store = self._get_bucket_info(Bucket)
        self._validate_transfer_config(Config)

        objects = bucket_info.setdefault("Objects", {})
        if Key not in objects:
            raise FileNotFoundError(f"Key {Key} does not exist")

        object_path = self._read_object_path(bucket_info, Key)
        with open(object_path, "rb") as f:
            content = f.read()

        object_meta = objects[Key]
        extra = ExtraArgs or {}
        checksum_mode = extra.get("ChecksumMode", "DISABLED")

        if checksum_mode == "ENABLED":
            algo = bucket_info.get("BucketConfiguration", {}).get("ChecksumAlgorithm", "SHA256")
            stored_checksum = object_meta["Checksum"]
            actual_checksum = compute_checksum(content, algo)
            if stored_checksum != actual_checksum:
                raise IOError("Checksum mismatch")

        os.makedirs(os.path.dirname(Filename), exist_ok=True)
        with open(Filename, "wb") as f:
            f.write(content)

        if Callback:
            Callback(object_meta["Size"])

    def get_object(self, **kwargs) -> Dict[str, Any]:
        bucket = kwargs.get("Bucket")
        key = kwargs.get("Key")
        version_id = kwargs.get("VersionId")
        part_number = kwargs.get("PartNumber")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        if not bucket:
            raise ValueError("Bucket name is required")
        if not key:
            raise ValueError("Key is required")

        if version_id:
            warnings.warn("Versioning not supported in local mock")
        if part_number:
            warnings.warn("Multipart download not supported in local mock")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        object_ = self._get_object_entry(bucket_info, key)
        object_path = os.path.join(self.base_path, bucket_info["BucketPath"], key)
        with open(object_path, "rb") as f:
            content = f.read()

        last_modified = datetime.fromisoformat(object_["LastModified"])
        precondition_result = self._evaluate_preconditions(object_, last_modified, kwargs)
        if precondition_result:
            return precondition_result

        content = self._apply_range(content, kwargs.get("Range"))
        checksums = self._compute_checksums_if_enabled(content, kwargs.get("ChecksumMode"))

        def build_object_response(content, object_, last_modified, checksums):
            return {
                "Body": MockStreamingBody(content),
                "LastModified": last_modified,
                "ContentLength": len(content),
                "ETag": object_["ETag"],
                "Metadata": object_.get("Metadata", {}),
                "ServerSideEncryption": "AES256",  # default for mock
                "SSEKMSKeyId": None,  # default for mock
                "BucketKeyEnabled": False,  # default for mock
                "DeleteMarker": False,  # default for mock
                "Expiration": None,  # default for mock
                "AcceptRanges": "bytes",
                "StorageClass": "STANDARD",
                "Restore": None,  # default for mock
                "MissingMeta": 0,  # default for mock
                "VersionId": "1",  # default version
                "ExpiresString": None,  # default for mock
                "WebsiteRedirectLocation": None,  # default for mock
                "ReplicationStatus": None,  # default for mock
                "PartsCount": None,  # default for mock
                "TagCount": 0,  # default for mock
                "ObjectLockMode": None,  # default for mock
                "ObjectLockRetainUntilDate": None,  # default for mock
                "ObjectLockLegalHoldStatus": None,  # default for mock
                **checksums,
            }

        def apply_response_overrides(response, kwargs):
            response_headers_map = {
                "ResponseCacheControl": "CacheControl",
                "ResponseContentDisposition": "ContentDisposition",
                "ResponseContentEncoding": "ContentEncoding",
                "ResponseContentLanguage": "ContentLanguage",
                "ResponseContentType": "ContentType",
                "ResponseExpires": "Expires",
            }
            for arg_key, resp_key in response_headers_map.items():
                if arg_key in kwargs:
                    response[resp_key] = kwargs[arg_key]

        def apply_optional_response_fields(response, kwargs):
            sse_cust_alg = kwargs.get("SSECustomerAlgorithm")
            sse_cust_key = kwargs.get("SSECustomerKey")
            req_payer = kwargs.get("RequesterPayer")

            if sse_cust_alg or sse_cust_key:
                warnings.warn("SSE-C is not supported in local mock, but fields will be echoed")
                response["SSECustomerAlgorithm"] = sse_cust_alg
                response["SSECustomerKeyMD5"] = sse_cust_key or None

            if req_payer == "requester":
                response["RequestCharged"] = "requester"

        response = build_object_response(content, object_, last_modified, checksums)
        apply_response_overrides(response, kwargs)
        apply_optional_response_fields(response, kwargs)

        return response

    def put_bucket_acl(self, **kwargs):
        acl = kwargs.get("ACL")
        bucket = kwargs.get("Bucket")
        checksum_algo = kwargs.get("ChecksumAlgorithm")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        if acl:
            bucket_info["ACL"] = acl

        grants = bucket_info.setdefault("Grants", {
            "FullControl": None,
            "Read": None,
            "ReadACP": None,
            "Write": None,
            "WriteACP": None
        })
        grant_keys = ["GrantFullControl", "GrantRead", "GrantReadACP", "GrantWrite", "GrantWriteACP"]
        for key in grant_keys:
            grant_type = key.replace("Grant", "")
            if kwargs.get(key):
                grants[grant_type] = kwargs[key]

        if kwargs.get("AccessControlPolicy"):
            bucket_info["AccessControlPolicy"] = kwargs["AccessControlPolicy"]
        if checksum_algo:
            Validator.s3_bucket_checksum_algorithm(checksum_algo)
            bucket_info["ChecksumAlgorithm"] = checksum_algo

        data_store[bucket] = bucket_info
        self._write_store(data_store)

    def get_bucket_acl(self, **kwargs) -> Dict[str, Any]:
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        grants_list = []
        acp = bucket_info.get("AccessControlPolicy", {})
        if acp.get("Grants"):
            grants_list = acp["Grants"]
        else:
            for perm_key, grantee_id in bucket_info.get("Grants", {}).items():
                if not grantee_id:
                    continue
                grants_list.append({
                    "Grantee": {"Type": "CanonicalUser", "ID": grantee_id},
                    "Permission": perm_key.upper(),
                })

        return {
            "Owner": bucket_info["Owner"],
            "Grants": grants_list
        }

    def put_public_access_block(self, **kwargs):
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")
        public_access_config = kwargs.get("PublicAccessBlockConfiguration")
        checksum_algorithm = kwargs.get("ChecksumAlgorithm")
        content_md5 = kwargs.get("ContentMD5")

        if not public_access_config:
            raise ValueError("PublicAccessBlockConfiguration is required")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        if checksum_algorithm:
            Validator.s3_bucket_checksum_algorithm(checksum_algorithm)
            bucket_info["ChecksumAlgorithm"] = checksum_algorithm
        if content_md5:
            bucket_info["ContentMD5"] = content_md5

        bucket_info.setdefault("PublicAccessBlockConfiguration", {})
        for key in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]:
            if key in public_access_config:
                bucket_info["PublicAccessBlockConfiguration"][key] = bool(public_access_config[key])

        data_store[bucket] = bucket_info
        self._write_store(data_store)

    def get_public_access_block(self, **kwargs) -> Dict[str, Any]:
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)

        return {
            "PublicAccessBlockConfiguration": bucket_info["PublicAccessBlockConfiguration"]
        }

    def delete_public_access_block(self, **kwargs):
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        bucket_info["PublicAccessBlockConfiguration"] = {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False
        }
        data_store[bucket] = bucket_info
        self._write_store(data_store)

    def put_bucket_policy(self, **kwargs):
        bucket = kwargs.get("Bucket")
        policy = kwargs.get("Policy")
        checksum_algorithm = kwargs.get("ChecksumAlgorithm")
        confirm_remove_self_access = kwargs.get("ConfirmRemoveSelfBucketAccess")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        if not policy:
            raise ValueError("Policy is required")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        if checksum_algorithm:
            Validator.s3_bucket_checksum_algorithm(checksum_algorithm)
            bucket_info["ChecksumAlgorithm"] = checksum_algorithm

        bucket_info["BucketPolicy"] = {
            "Policy": policy,
            "ConfirmRemoveSelfBucketAccess": confirm_remove_self_access,
            "CreatedDate": datetime.now(timezone.utc).isoformat(),
        }

        data_store[bucket] = bucket_info
        self._write_store(data_store)

    def get_bucket_policy(self, **kwargs) -> Dict[str, Any]:
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        bucket_policy = bucket_info.setdefault("BucketPolicy", {}).get("Policy", None)

        return {
            "Policy": bucket_policy,
        }

    def get_bucket_policy_status(self, **kwargs) -> Dict[str, Any]:
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        is_public = False
        pab = bucket_info.setdefault("PublicAccessBlockConfiguration", {})
        block_all = (
                pab.get("BlockPublicAcls", False) or
                pab.get("IgnorePublicAcls", False) or
                pab.get("BlockPublicPolicy", False) or
                pab.get("RestrictPublicBuckets", False)
        )
        policy_json = bucket_info.setdefault("BucketPolicy", {}).get("Policy")
        if policy_json and not block_all:
            try:
                policy = json.loads(policy_json)
                for stmt in policy.get("Statement", []):
                    principal = stmt.get("Principal")
                    effect = stmt.get("Effect")
                    if principal == "*" and effect == "Allow":
                        is_public = True
                        break
            except Exception:
                pass

        return {
            "PolicyStatus": {
                "IsPublic":
                    is_public
            }
        }

    def delete_bucket_policy(self, **kwargs):
        bucket = kwargs.get("Bucket")
        expected_owner = kwargs.get("ExpectedBucketOwner")

        bucket_info, data_store = self._get_bucket_info(bucket, expected_owner)
        if "BucketPolicy" in bucket_info:
            del bucket_info["BucketPolicy"]

        data_store[bucket] = bucket_info
        self._write_store(data_store)
