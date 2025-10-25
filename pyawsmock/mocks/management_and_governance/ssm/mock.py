import base64
import os
import re
import uuid
import warnings
from datetime import datetime, timezone
from typing import Dict, Any

from pyawsmock.mocks.base_mock import MockBase
from pyawsmock.mocks.store_utils import StoreUtils


class MockSSMValidator:
    NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.\-/]+$")
    TAG_PATTERN = re.compile(r"^[\w\s_.:/=+\-@]+$")
    KMS_PATTERNS = [
        re.compile(r"^arn:(aws|mock):kms:[a-z0-9-]+:\d{12}:key/[a-f0-9-]{36}$"),
        re.compile(r"^alias/[a-zA-Z0-9/_+=,.@-]+$"),
        re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"),
        re.compile(r"^arn:mock:kms:(local(-[a-z0-9-]+)?):\d{12}:key/[a-f0-9-]{36}$"),
    ]

    @staticmethod
    def _raise_if(condition, message):
        if condition:
            raise ValueError(message)

    @classmethod
    def name(cls, name: str):
        cls._raise_if(not name, "Name is required")
        cls._raise_if(len(name) > 1011, "Parameter name exceeds max length (1011 chars)")
        cls._raise_if(not cls.NAME_PATTERN.match(name), "Invalid characters in parameter name")
        cls._raise_if(name.lower().startswith(("/aws", "/ssm", "aws", "ssm")),
                      "Parameter name cannot start with 'aws' or 'ssm'")
        cls._raise_if(name.count("/") > 15, "Parameter hierarchy exceeds max depth (15 levels)")

    @classmethod
    def value(cls, value: str, tier: str):
        cls._raise_if(not value, "Value is required")
        max_size = 4096 if tier == "Standard" else 8192
        cls._raise_if(len(value.encode("utf-8")) > max_size,
                      f"{tier} parameter value exceeds {max_size // 1024}KB")

    @classmethod
    def type(cls, type_: str):
        cls._raise_if(type_ not in ["String", "StringList", "SecureString"],
                      "Invalid type. Supported are: String, StringList, SecureString")

    @classmethod
    def tier(cls, tier: str):
        cls._raise_if(tier not in ["Standard", "Advanced", "Intelligent-Tiering"],
                      "Invalid tier. Supported are: Standard, Advanced, Intelligent-Tiering")

    @classmethod
    def data_type(cls, type_: str):
        cls._raise_if(type_ not in ["text", "aws:ec2:image", "aws:ssm:integration"],
                      "Invalid data type. Supported are: text, aws:ec2:image, aws:ssm:integration")

    @classmethod
    def kms_key(cls, key_id: str):
        cls._raise_if(
            not any(p.match(key_id) for p in cls.KMS_PATTERNS),
            f"Invalid KeyId format: {key_id}. Expected AWS/Mock KMS ARN, alias, or UUID."
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


Validator = MockSSMValidator


class MockSSM(MockBase):
    _supported_methods = [
        "put_parameter",
        "get_parameter",
        "get_parameters",
        "get_parameters_by_path",
        "get_parameter_history",
        "label_parameter_version",
        "delete_parameter",
        "delete_parameters",
        "unlabel_parameter_version",
        "describe_parameters",
    ]

    def __init__(self, base_path, region_name):
        self.region_name = region_name
        self.store_path = base_path / region_name / "ssm_parameters.json"
        self.lock_path = f"{self.store_path}.lock"
        os.makedirs(self.store_path.parent, exist_ok=True)
        if not self.store_path.exists():
            self._write_store({})

    def _read_store(self):
        return StoreUtils.read_json_gzip(self.store_path)

    def _write_store(self, data):
        StoreUtils.write_json_gzip(self.store_path, data, self.lock_path)

    def _decode_secure_value(self, value, param_type, with_decryption):
        if param_type == "SecureString" and with_decryption:
            value = base64.b64decode(value.encode()).decode()
        return value

    def _apply_filters(self, params, filters):
        if not filters:
            return params

        def match_param(param, f):
            key = f.get("Key")
            option = f.get("Option", "Equals")
            values = f.get("Values", [])

            if key == "Label":
                param_value = []
                for v in param["Versions"].values():
                    param_value.extend(v.get("Labels", []))
            else:
                param_value = param.get(key)
                if param_value is None:
                    return False

            for v in values:
                if key == "Label" and option == "Equals" and v in param_value:
                    return True
                elif key != "Label":
                    if option == "Equals" and param_value == v:
                        return True
                    elif option == "BeginsWith" and str(param_value).startswith(v):
                        return True
                    elif option == "Contains" and v in str(param_value):
                        return True
            return False

        filtered = []
        for param in params:
            if all(match_param(param, f) for f in filters):
                filtered.append(param)
        return filtered

    def _paginate_list(self, items, max_results=None, next_token=None):
        try:
            start_index = int(next_token) if next_token is not None else 0
        except ValueError:
            start_index = 0

        end_index = len(items)
        if max_results is not None:
            end_index = min(start_index + max_results, len(items))
            next_token = str(end_index) if end_index < len(items) else None
        else:
            next_token = None
        return items[start_index:end_index], next_token

    def _get_latest_version(self, param, selector=None):
        if selector is None:
            latest_version = max(param["Versions"].keys())
            return param["Versions"][latest_version]
        return None

    def _get_version_data(self, param, version):
        versions = param.get("Versions", {})
        if not versions:
            raise ValueError(f"No versions found for parameter '{param['Name']}'")
        if version is None:
            version = max(int(v) for v in versions.keys())
        if version not in map(int, versions.keys()):
            raise ValueError(f"Version {version} does not exist for parameter '{param['Name']}'")
        return versions[f"{version}"], version, versions

    def _create_and_update_param(self, data_store, name, value, kwargs):
        existing = data_store.get(name)
        if existing and not kwargs.get("Overwrite", False):
            raise ValueError(f"Parameter {name} already exists")
        version = (max(map(int, existing["Versions"])) + 1) if existing else 1
        version_entry = {
            "Value": value,
            "Labels": [],
            "Version": version,
            "LastModifiedDate": datetime.now(timezone.utc).isoformat(),
            "LastModifiedUser": "arn:mock:iam::000000000000:user/local-mock",
        }

        meta = {
            "Name": name,
            "Description": kwargs.get("Description"),
            "Value": value,
            "Type": kwargs.get("Type", "String"),
            "KeyId": kwargs.get("KeyId"),
            "AllowedPattern": kwargs.get("AllowedPattern"),
            "Tags": kwargs.get("Tags", []),
            "Tier": kwargs.get("Tier", "Standard"),
            "Policies": kwargs.get("Policies"),
            "DataType": kwargs.get("DataType", "text"),
            "ARN": f"arn:mock:ssm:{self.region_name}:000000000000:parameter/{name.lstrip('/')}",
            "Selector": None,
            "SourceResult": None,
            "RequestId": str(uuid.uuid4()),
        }

        if existing:
            existing["Versions"][version] = version_entry
            existing.update(meta)
            data_store[name] = existing
        else:
            data_store[name] = {**meta, "Versions": {version: version_entry}}

        return data_store, version_entry

    def _get_param_version(self, param, selector):
        if not selector:
            latest_version = max(map(int, param["Versions"]))
            return param["Versions"][str(latest_version)]

        if selector.isdigit():
            v = int(selector)
            if str(v) not in param["Versions"]:
                raise ValueError(f"Version {v} not found")
            return param["Versions"][str(v)]

        # Label lookup
        for vdata in param["Versions"].values():
            if selector in vdata.get("Labels", []):
                return vdata
        raise ValueError(f"Label {selector} not found")

    def put_parameter(self, **kwargs) -> Dict[str, Any]:
        name = kwargs.get("Name")
        value = kwargs.get("Value")
        type_ = kwargs.get("Type", "String")
        key_id = kwargs.get("KeyId")
        allowed_pattern = kwargs.get("AllowedPattern")
        tags = kwargs.get("Tags", [])
        tier = kwargs.get("Tier", "Standard")
        data_type = kwargs.get("DataType", "text")

        Validator.name(name)
        Validator.tier(tier)
        Validator.value(value, tier)
        Validator.type(type_)
        Validator.data_type(data_type)
        Validator.tags(tags)

        if allowed_pattern and not re.match(allowed_pattern, value):
            raise ValueError(f"Value does not match AllowedPattern: {allowed_pattern}")

        if type_ == "SecureString":
            if not key_id:
                raise ValueError("KMS Key Id is required when using SecureString")
            Validator.kms_key(key_id)
            value = base64.b64encode(value.encode()).decode()

        data_store = self._read_store()
        data_store, version_entry = self._create_and_update_param(data_store, name, value, kwargs)
        self._write_store(data_store)

        return {
            "Version": version_entry["Version"],
            "Tier": tier
        }

    def get_parameter(self, **kwargs) -> Dict[str, Any]:
        name = kwargs.get("Name")
        with_decryption = kwargs.get("WithDecryption", False)
        if not name:
            raise ValueError("Name is required")

        arn_pattern = r"^arn:(aws|mock):ssm:[a-z0-9-]+:\d{12}:parameter(/.+)$"
        match = re.match(arn_pattern, name)
        if match:
            name = match.group(2)

        selector = None
        if ":" in name:
            name, selector = name.split(":", 1)

        data_store = self._read_store()
        param = data_store.get(name)
        if not param:
            raise ValueError(f"Parameter '{name}' not found in region '{self.region_name}'")

        param_version = self._get_param_version(param, selector)
        value = self._decode_secure_value(param_version["Value"], param["Type"], with_decryption)

        return {
            "Parameter": {
                "Name": name,
                "Type": param["Type"],
                "Value": value,
                "Version": param_version.get("Version", 1),
                "Selector": f"{param['Name']}:{selector}" if selector else None,
                "SourceResult": None,
                "LastModifiedDate": datetime.fromisoformat(param_version.get("LastModifiedDate")),
                "ARN": param["ARN"],
                "DataType": param.get("DataType", "text"),
            }
        }

    def get_parameters(self, **kwargs) -> Dict[str, Any]:
        names = kwargs.get("Names")
        with_decryption = kwargs.get("WithDecryption", False)
        if not names or not isinstance(names, list):
            raise ValueError("Names must be a non-empty list of parameter names or ARNs")

        response_params, invalid_params = [], []
        for name in names:
            try:
                param_response = self.get_parameter(Name=name, WithDecryption=with_decryption)
                response_params.append(param_response["Parameter"])
            except Exception:
                invalid_params.append(name)

        response_params.sort(key=lambda x: x["Name"])

        return {
            "Parameters": response_params,
            "InvalidParameters": invalid_params
        }

    def get_parameters_by_path(self, **kwargs) -> Dict[str, Any]:
        path = kwargs.get("Path")
        recursive = kwargs.get("Recursive", False)
        param_filters = kwargs.get("ParameterFilters")
        with_decryption = kwargs.get("WithDecryption", False)
        max_results = kwargs.get("MaxResults")
        next_token = kwargs.get("NextToken")
        if not path or not path.startswith("/"):
            raise ValueError("Path must start with '/'")

        all_params = list(self._read_store().values())
        matching_params = [
            p for p in all_params
            if (p["Name"].startswith(path) if recursive else "/" not in p["Name"][len(path):].lstrip("/"))
        ]

        filtered_params = self._apply_filters(matching_params, param_filters)
        filtered_params.sort(key=lambda x: x["Name"])

        page, next_token = self._paginate_list(filtered_params, max_results, next_token)

        response_list = []
        for p in page:
            latest_version = max(p["Versions"].keys())
            version_data = p["Versions"][latest_version]
            value = self._decode_secure_value(version_data["Value"], p["Type"], with_decryption)

            response_list.append({
                "Name": p["Name"],
                "Type": p["Type"],
                "Value": value,
                "Version": latest_version,
                "Selector": None,
                "SourceResult": None,
                "LastModifiedDate": version_data["LastModifiedDate"],
                "ARN": p["ARN"],
                "DataType": p.get("DataType", "text")
            })

        return {
            "Parameters": response_list,
            "NextToken": next_token
        }

    def get_parameter_history(self, **kwargs) -> Dict[str, Any]:
        name = kwargs.get("Name")
        with_decryption = kwargs.get("WithDecryption", False)
        max_results = kwargs.get("MaxResults")
        next_token = kwargs.get("NextToken")
        if not name:
            raise ValueError("Name is required")

        param = self._read_store().get(name)
        if not param:
            raise ValueError(f"Parameter '{name}' not found")

        versions = sorted(param.get("Versions", {}).items(), key=lambda x: x[0], reverse=True)
        page, next_token = self._paginate_list(versions, max_results, next_token)

        response_list = []
        for version_num, version_data in page:
            value = self._decode_secure_value(version_data["Value"], param["Type"], with_decryption)
            response_list.append({
                "Name": param["Name"],
                "Type": param["Type"],
                "KeyId": param.get("KeyId"),
                "LastModifiedDate": version_data["LastModifiedDate"],
                "LastModifiedUser": version_data.get("LastModifiedUser"),
                "Description": param.get("Description"),
                "Value": value,
                "AllowedPattern": param.get("AllowedPattern"),
                "Version": version_num,
                "Labels": version_data.get("Labels", []),
                "Tier": param.get("Tier"),
                "Policies": param.get("Policies", []),
                "DataType": param.get("DataType", "text")
            })

        return {
            "Parameters": response_list,
            "NextToken": next_token
        }

    def label_parameter_version(self, **kwargs) -> Dict[str, Any]:
        name = kwargs.get("Name")
        parameter_version = kwargs.get("ParameterVersion")
        labels = kwargs.get("Labels")

        if not name:
            raise ValueError("Name is required")
        if not labels or not isinstance(labels, list):
            raise ValueError("Labels must be a non-empty list")

        data_store = self._read_store()
        param = data_store.get(name)
        if not param:
            raise ValueError(f"Parameter '{name}' not found")

        version_data, version, versions = self._get_version_data(param, parameter_version)

        invalid_labels = []
        for label in labels:
            if not isinstance(label, str) or not label or not re.match(r'^[a-zA-Z0-9_.-]+$', label):
                invalid_labels.append(label)
                continue
            if label not in version_data.setdefault("Labels", []):
                version_data["Labels"].append(label)

        versions[str(version)] = version_data
        data_store[name]["Versions"] = versions
        self._write_store(data_store)

        return {
            "InvalidLabels": invalid_labels,
            "ParameterVersion": version
        }

    def unlabel_parameter_version(self, **kwargs) -> Dict[str, Any]:
        name = kwargs.get("Name")
        parameter_version = kwargs.get("ParameterVersion")
        labels = kwargs.get("Labels")

        if not name:
            raise ValueError("Name is required")
        if parameter_version is None:
            raise ValueError("ParameterVersion is required")
        if not labels or not isinstance(labels, list):
            raise ValueError("Labels must be a non-empty list")

        labels = list(dict.fromkeys(labels))
        data_store = self._read_store()
        param = data_store.get(name)
        if not param:
            raise ValueError(f"Parameter '{name}' not found")

        version_data, version, versions = self._get_version_data(param, parameter_version)

        removed_labels = []
        invalid_labels = []

        existing_labels = version_data.get("Labels", [])
        for label in labels:
            if label in existing_labels:
                existing_labels.remove(label)
                removed_labels.append(label)
            else:
                invalid_labels.append(label)

        version_data["Labels"] = existing_labels
        versions[str(version)] = version_data
        data_store[name]["Versions"] = versions
        self._write_store(data_store)

        return {
            "RemovedLabels": removed_labels,
            "InvalidLabels": invalid_labels
        }

    def delete_parameter(self, **kwargs) -> dict:
        name = kwargs.get("Name")
        if not name:
            raise ValueError("Name is required")

        data_store = self._read_store()
        if name not in data_store:
            raise ValueError(f"Parameter '{name}' not found")

        del data_store[name]
        self._write_store(data_store)
        return {}

    def delete_parameters(self, **kwargs) -> Dict[str, Any]:
        names = kwargs.get("Names")
        if not names or not isinstance(names, list):
            raise ValueError("Names must be a non-empty list of parameter names")

        deleted_params, invalid_params = [], []
        for name in names:
            try:
                self.delete_parameter(Name=name)
                deleted_params.append(name)
            except Exception:
                invalid_params.append(name)

        return {
            "DeletedParameters": deleted_params,
            "InvalidParameters": invalid_params,
        }

    def describe_parameters(self, **kwargs) -> Dict[str, Any]:
        param_filters = kwargs.get("ParameterFilters")
        max_results = kwargs.get("MaxResults")
        next_token = kwargs.get("NextToken")
        shared = kwargs.get("Shared", False)
        if shared:
            warnings.warn("Shared is not supported in local mock")

        all_params = list(self._read_store().values())
        filtered_params = self._apply_filters(all_params, param_filters)
        filtered_params.sort(key=lambda x: x["Name"])

        page, next_token = self._paginate_list(filtered_params, max_results, next_token)

        response_list = []
        for p in page:
            latest_version = max(p["Versions"].keys())
            version_data = p["Versions"][latest_version]

            response_list.append({
                "Name": p["Name"],
                "ARN": p["ARN"],
                "Type": p["Type"],
                "KeyId": p.get("KeyId"),
                "LastModifiedDate": version_data.get("LastModifiedDate"),
                "LastModifiedUser": version_data.get("LastModifiedUser"),
                "Description": p.get("Description"),
                "AllowedPattern": p.get("AllowedPattern"),
                "Version": latest_version,
                "Tier": p.get("Tier"),
                "Policies": p.get("Policies", []),
                "DataType": p.get("DataType", "text"),
            })

        return {
            "Parameters": response_list,
            "NextToken": next_token
        }
