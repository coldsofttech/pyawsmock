import os
import re
import uuid
import warnings
from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict, Any

from pyawsmock.mocks.base_mock import MockBase
from pyawsmock.mocks.store_utils import StoreUtils


class MockCloudFrontValidator:
    TAG_PATTERN = re.compile(r"^[\w\s_.:/=+\-@]+$")

    @staticmethod
    def _raise_if(condition, message):
        if condition:
            raise ValueError(message)

    @classmethod
    def oai_config(cls, config: dict):
        cls._raise_if(not config, "CloudFrontOriginAccessIdentityConfig is required")
        cls._raise_if(not config.get("CallerReference"), "CallerReference is required")
        cls._raise_if(not config.get("Comment"), "Comment is required")
        cls._raise_if(len(config.get("Comment")) > 128, "Comment max 128 characters")

    @classmethod
    def dist_config(cls, config: dict):
        cls._raise_if(not config, "DistributionConfig is required")
        cls._raise_if(not config.get("CallerReference"), "CallerReference is required")
        cls._raise_if(not config.get("Comment"), "Comment is required")
        cls._raise_if(len(config.get("Comment")) > 128, "Comment max 128 characters")

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


Validator = MockCloudFrontValidator


class MockCloudFront(MockBase):
    _supported_methods = [
        "create_cloud_front_origin_access_identity",
        "get_cloud_front_origin_access_identity",
        "get_cloud_front_origin_access_identity_config",
        "delete_cloud_front_origin_access_identity",
        "create_distribution",
        "get_distribution",
        "get_distribution_config",
        "update_distribution",
        "delete_distribution",
    ]

    def __init__(self, base_path):
        self.base_path = base_path
        self.dist_store_path = base_path / "cloudfront_distributions.json"
        self.oai_store_path = base_path / "cloudfront_oais.json"
        self.data_path = base_path / "global" / "CloudFront"
        os.makedirs(self.data_path, exist_ok=True)
        self.oai_lock_path = f"{self.oai_store_path}.lock"
        self.dist_lock_path = f"{self.dist_store_path}.lock"
        os.makedirs(self.oai_store_path.parent, exist_ok=True)
        if not self.oai_store_path.exists():
            self._write_oai_store({})
        if not self.dist_store_path.exists():
            self._write_dist_store({})

    def _read_oai_store(self):
        return StoreUtils.read_json_gzip(self.oai_store_path)

    def _read_dist_store(self):
        return StoreUtils.read_json_gzip(self.dist_store_path)

    def _write_oai_store(self, data):
        StoreUtils.write_json_gzip(self.oai_store_path, data, self.oai_lock_path)

    def _write_dist_store(self, data):
        StoreUtils.write_json_gzip(self.dist_store_path, data, self.dist_lock_path)

    def _get_origin_access_identity_info(self, id_):
        if not id_:
            raise ValueError("Id is required")
        data_store = self._read_oai_store()
        if id_ not in data_store:
            raise ValueError(f"Id '{id_}' does not exist")
        return data_store[id_], data_store

    def _get_distribution_info(self, id_):
        if not id_:
            raise ValueError("Id is required")
        data_store = self._read_dist_store()
        if id_ not in data_store:
            raise ValueError(f"Id '{id_}' does not exist")
        return data_store[id_], data_store

    def create_cloud_front_origin_access_identity(self, **kwargs) -> Dict[str, Any]:
        config = kwargs.get("CloudFrontOriginAccessIdentityConfig")
        Validator.oai_config(config)
        caller_reference = config.get("CallerReference")
        comment = config.get("Comment")
        data_store = self._read_oai_store()
        for existing_identity in data_store.values():
            if existing_identity["CloudFrontOriginAccessIdentityConfig"]["CallerReference"] == caller_reference:
                if existing_identity["CloudFrontOriginAccessIdentityConfig"] == config:
                    return {
                        "CloudFrontOriginAccessIdentity": existing_identity,
                        "Location": f"/2020-05-31/origin-access-identity/cloudfront/{existing_identity['Id']}",
                        "ETag": existing_identity["ETag"]
                    }
                else:
                    raise ValueError("CloudFrontOriginAccessIdentity already exists")

        identity_id = "E" + str(uuid.uuid4()).replace("-", "")[:12].upper()
        s3_canonical_user_id = sha256(uuid.uuid4().bytes).hexdigest()
        etag = str(uuid.uuid4())

        identity = {
            "Id": identity_id,
            "S3CanonicalUserId": s3_canonical_user_id,
            "CloudFrontOriginAccessIdentityConfig": {
                "CallerReference": caller_reference,
                "Comment": comment
            },
            "ETag": etag
        }

        data_store[identity_id] = identity
        self._write_oai_store(data_store)

        return {
            "CloudFrontOriginAccessIdentity": identity,
            "Location": f"/2020-05-31/origin-access-identity/cloudfront/{identity_id}",
            "ETag": etag
        }

    def get_cloud_front_origin_access_identity(self, **kwargs) -> Dict[str, Any]:
        id_ = kwargs.get("Id")
        identity_info, data_store = self._get_origin_access_identity_info(id_)

        return {
            "CloudFrontOriginAccessIdentity": {
                "Id": identity_info["Id"],
                "S3CanonicalUserId": identity_info["S3CanonicalUserId"],
                "CloudFrontOriginAccessIdentityConfig": identity_info["CloudFrontOriginAccessIdentityConfig"],
            },
            "ETag": identity_info["ETag"],
        }

    def get_cloud_front_origin_access_identity_config(self, **kwargs) -> Dict[str, Any]:
        id_ = kwargs.get("Id")
        identity_info, data_store = self._get_origin_access_identity_info(id_)
        oai_config = identity_info.setdefault("CloudFrontOriginAccessIdentityConfig", {})

        return {
            "CloudFrontOriginAccessIdentityConfig": {
                "CallerReference": oai_config["CallerReference"],
                "Comment": oai_config["Comment"],
            },
            "ETag": identity_info["ETag"],
        }

    def delete_cloud_front_origin_access_identity(self, **kwargs):
        id_ = kwargs.get("Id")
        if_match = kwargs.get("IfMatch")

        identity_info, data_store = self._get_origin_access_identity_info(id_)
        if if_match:
            if identity_info["ETag"] != if_match:
                raise ValueError("ETag does not match")

        del data_store[id_]
        self._write_oai_store(data_store)

    def create_distribution(self, **kwargs) -> Dict[str, Any]:
        config = kwargs.get("DistributionConfig")
        Validator.dist_config(config)
        caller_reference = config.get("CallerReference")
        warnings.warn("Please note local mock does not perform complete validation of DistributionConfig")
        data_store = self._read_dist_store()
        for dist in data_store.values():
            if dist["DistributionConfig"]["CallerReference"] == caller_reference:
                return {
                    "Distribution": dist,
                    "Location": f"/2020-05-31/distribution/{dist['Id']}",
                    "ETag": dist["ETag"]
                }

        dist_id = "ED" + str(uuid.uuid4()).replace("-", "")[:12].upper()
        etag = str(uuid.uuid4())
        domain_name = f"{dist_id}.cloudfront.{self._mock_domain}"
        last_modified = datetime.now(timezone.utc).isoformat()
        distribution = {
            "Id": dist_id,
            "ARN": f"arn:mock:cloudfront::000000000000:distribution/{dist_id}",
            "Status": "Deployed",
            "LastModifiedTime": last_modified,
            "DomainName": domain_name,
            "ETag": etag,
            "DistributionConfig": config
        }
        data_store[dist_id] = distribution
        self._write_dist_store(data_store)

        return {
            "Distribution": distribution,
            "Location": f"/2020-05-31/distribution/{dist_id}",
            "ETag": etag
        }

    def get_distribution(self, **kwargs) -> Dict[str, Any]:
        id_ = kwargs.get("Id")
        dist_info, data_store = self._get_distribution_info(id_)

        return {
            "Distribution": {
                "Id": dist_info["Id"],
                "ARN": dist_info["ARN"],
                "Status": dist_info.get("Status", "Deployed"),
                "LastModifiedTime": datetime.fromisoformat(dist_info.get("LastModifiedTime")),
                "InProgressInvalidationBatches": dist_info.get("InProgressInvalidationBatches", 0),
                "DomainName": dist_info.get("DomainName"),
                "ActiveTrustedSigners": dist_info.get("ActiveTrustedSigners", {
                    "Enabled": False, "Quantity": 0, "Items": []
                }),
                "ActiveTrustedKeyGroups": dist_info.get("ActiveTrustedKeyGroups", {
                    "Enabled": False, "Quantity": 0, "Items": []
                }),
                "DistributionConfig": dist_info["DistributionConfig"],
                "AliasICPRecordals": dist_info.get("AliasICPRecordals", [])
            },
            "ETag": dist_info.get("ETag")
        }

    def get_distribution_config(self, **kwargs) -> Dict[str, Any]:
        id_ = kwargs.get("Id")
        dist_info, data_store = self._get_distribution_info(id_)

        return {
            "DistributionConfig": dist_info["DistributionConfig"],
            "ETag": dist_info.get("ETag")
        }

    def update_distribution(self, **kwargs) -> Dict[str, Any]:
        config = kwargs.get("DistributionConfig")
        if_match = kwargs.get("IfMatch")
        id_ = kwargs.get("Id")
        Validator.dist_config(config)
        if not if_match:
            raise ValueError("IfMatch is required")
        warnings.warn("Please note local mock does not perform complete validation of DistributionConfig")
        dist_info, data_store = self._get_distribution_info(id_)
        if if_match != dist_info["ETag"]:
            raise ValueError("ETag does not match")
        dist_info["DistributionConfig"] = config
        dist_info["ETag"] = str(uuid.uuid4())
        dist_info["LastModifiedTime"] = datetime.now(timezone.utc).isoformat()
        data_store[id_] = dist_info
        self._write_dist_store(data_store)

        return {
            "Distribution": {
                "Id": dist_info["Id"],
                "ARN": dist_info.get("ARN"),
                "Status": dist_info.get("Status", "Deployed"),
                "LastModifiedTime": datetime.fromisoformat(dist_info["LastModifiedTime"]),
                "InProgressInvalidationBatches": dist_info.get("InProgressInvalidationBatches", 0),
                "DomainName": dist_info.get("DomainName"),
                "DistributionConfig": config,
            },
            "ETag": dist_info["ETag"]
        }

    def delete_distribution(self, **kwargs):
        if_match = kwargs.get("IfMatch")
        id_ = kwargs.get("Id")
        dist_info, data_store = self._get_distribution_info(id_)
        if not if_match:
            raise ValueError("IfMatch is required")
        if if_match != dist_info["ETag"]:
            raise ValueError("ETag does not match")
        dist_config = dist_info.get("DistributionConfig", {})
        if dist_config.get("Enabled", True):
            raise ValueError("Cannot delete a distribution that is enabled. Disable it first.")

        del data_store[id_]
        self._write_dist_store(data_store)
