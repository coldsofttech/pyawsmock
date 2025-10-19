import base64
import gzip
import json
import os
import re
import uuid
import warnings
from datetime import datetime, timezone
from typing import Dict, Any

from pyawsmock.mocks.base_mock import MockBase


def validate_parameter_name(name: str):
    if not name:
        raise ValueError("Name is required")
    if len(name) > 1011:
        raise ValueError("Parameter name exceeds max length (1011 chars)")
    if not re.match(r"^[a-zA-Z0-9_.\-/]+$", name):
        raise ValueError("Invalid characters in parameter name")
    if name.lower().startswith(("/aws", "/ssm", "aws", "ssm")):
        raise ValueError("Parameter name cannot start with 'aws' or 'ssm'")
    if name.count("/") > 15:
        raise ValueError("Parameter hierarchy exceeds max depth (15 levels)")


def validate_parameter_value(value: str, tier: str):
    if tier == "Standard" and len(value.encode("utf-8")) > 4096:
        raise ValueError("Standard parameter value exceeds 4KB")
    if tier == "Advanced" and len(value.encode("utf-8")) > 8192:
        raise ValueError("Advanced parameter value exceeds 8KB")


def validate_parameter_type(type_: str):
    if type_ not in ["String", "StringList", "SecureString"]:
        raise ValueError("Invalid type. Supported are: String, StringList, SecureString")


def validate_kms_key_id(key_id: str):
    arn_pattern = r"^arn:(aws|mock):kms:[a-z0-9-]+:\d{12}:key/[a-f0-9-]{36}$"
    alias_pattern = r"^alias/[a-zA-Z0-9/_+=,.@-]+$"
    uuid_pattern = r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
    local_arn_pattern = r"^arn:mock:kms:(local(-[a-z0-9-]+)?):\d{12}:key/[a-f0-9-]{36}$"

    if not (
            re.match(arn_pattern, key_id)
            or re.match(alias_pattern, key_id)
            or re.match(uuid_pattern, key_id)
            or re.match(local_arn_pattern, key_id)
    ):
        raise ValueError(
            f"Invalid KeyId format: {key_id}. Expected a valid AWS or Mock KMS ARN, alias, or key ID UUID."
        )


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


def validate_parameter_tier(tier: str):
    if tier not in ["Standard", "Advanced", "Intelligent-Tiering"]:
        raise ValueError("Invalid tier. Supported are: Standard, Advanced, or Intelligent-Tiering")


def validate_parameter_data_type(type_: str):
    if type_ not in ["text", "aws:ec2:image", "aws:ssm:integration"]:
        raise ValueError("Invalid data type. Supported are: text, aws:ec2:image or aws:ssm")


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
            with gzip.open(self.store_path, "wb") as f:
                f.write(json.dumps({}, indent=4).encode("utf-8"))

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

    def put_parameter(self, **kwargs) -> Dict[str, Any]:
        name = kwargs.get("Name")
        description = kwargs.get("Description")
        value = kwargs.get("Value")
        type_ = kwargs.get("Type", "String")
        key_id = kwargs.get("KeyId")
        overwrite = kwargs.get("Overwrite", False)
        allowed_pattern = kwargs.get("AllowedPattern")
        tags = kwargs.get("Tags", [])
        tier = kwargs.get("Tier", "Standard")
        policies = kwargs.get("Policies")
        data_type = kwargs.get("DataType", "text")

        if name is None:
            raise ValueError("Missing required parameters: Name")
        if value is None:
            raise ValueError("Missing required parameters: Value")

        validate_parameter_name(name)
        validate_parameter_tier(tier)
        validate_parameter_type(type_)
        validate_parameter_value(value, tier)
        validate_parameter_data_type(data_type)
        validate_tags(tags)

        if allowed_pattern and not re.match(allowed_pattern, value):
            raise ValueError(f"Value does not match AllowedPattern: {allowed_pattern}")

        if type_ == "SecureString":
            if not key_id:
                raise ValueError("KMS Key Id is required when using SecureString")
            else:
                validate_kms_key_id(key_id)

            value = base64.b64encode(value.encode()).decode()

        data_store = self._read_store()
        existing = data_store.get(name)
        if existing and not overwrite:
            raise ValueError(f"Parameter '{name}' already exists. Use Overwrite=True to overwrite.")

        if existing:
            latest_version = max(int(v) for v in existing["Versions"].keys())
            version = latest_version + 1
        else:
            version = 1

        version_entry = {
            "Value": value,
            "Labels": [],
            "Version": version,
            "LastModifiedDate": datetime.now(timezone.utc).isoformat(),
            "LastModifiedUser": "arn:mock:iam::000000000000:user/local-mock",
        }

        if existing:
            existing["Versions"][version] = version_entry
            existing.update({
                "Description": description,
                "Type": type_,
                "KeyId": key_id,
                "AllowedPattern": allowed_pattern,
                "Tags": tags or [],
                "Tier": tier,
                "Policies": policies,
                "DataType": data_type,
                "ARN": f"arn:mock:ssm:{self.region_name}:000000000000:parameter/{name.lstrip('/')}",
                "Selector": None,
                "SourceResult": None,
                "RequestId": str(uuid.uuid4()),
            })
            data_store[name] = existing
        else:
            data_store[name] = {
                "Name": name,
                "Description": description,
                "Value": value,
                "Type": type_,
                "KeyId": key_id,
                "AllowedPattern": allowed_pattern,
                "Tags": tags or [],
                "Tier": tier,
                "Policies": policies,
                "DataType": data_type,
                "Versions": {version: version_entry},
                "ARN": f"arn:mock:ssm:{self.region_name}:000000000000:parameter/{name.lstrip('/')}",
                "Selector": None,
                "SourceResult": None,
                "RequestId": str(uuid.uuid4()),
            }

        self._write_store(data_store)

        return {
            "Version": version,
            "Tier": tier
        }

    def get_parameter(self, **kwargs) -> Dict[str, Any]:
        name = kwargs.get("Name")
        with_decryption = kwargs.get("WithDecryption", False)

        if not name:
            raise ValueError("Missing required parameters: Name")

        arn_pattern = r"^arn:(aws|mock):ssm:[a-z0-9-]+:\d{12}:parameter(/.+)$"
        match = re.match(arn_pattern, name)
        if match:
            name = match.group(2).lstrip("/")

        selector = None
        if ":" in name:
            name, selector = name.split(":", 1)

        data_store = self._read_store()
        param = data_store.get(name)

        if not param:
            raise ValueError(f"Parameter '{name}' not found in region '{self.region_name}'")

        if selector:
            if selector.isdigit():
                version = int(selector)
                if version not in param["Versions"]:
                    raise ValueError(f"Version {selector} not found for parameter '{name}'")
                param_version = param["Versions"][version]
            else:
                found = None
                for ver, vdata in param["Versions"].items():
                    if selector in vdata.get("Labels", []):
                        found = vdata
                        break
                if not found:
                    raise ValueError(f"Label {selector} not found for parameter '{name}'")
                param_version = found
        else:
            latest_version = max(param["Versions"])
            param_version = param["Versions"][latest_version]

        value = param_version["Value"]
        if param["Type"] == "SecureString":
            if with_decryption:
                try:
                    value = base64.b64decode(value.encode()).decode()
                except Exception as e:
                    raise ValueError(f"Failed to decode value: {e}")

        return {
            "Parameter": {
                "Name": name,
                "Type": param["Type"],
                "Value": value,
                "Version": param_version.get("Version", 1),
                "Selector": f"{param['Name']}:{selector}" if selector else None,
                "SourceResult": None,
                "LastModifiedDate": datetime.fromisoformat(param_version.get("LastModifiedDate", None)),
                "ARN": param["ARN"],
                "DataType": param.get("DataType", "text"),
            }
        }

    def get_parameters(self, **kwargs) -> Dict[str, Any]:
        names = kwargs.get("Names")
        with_decryption = kwargs.get("WithDecryption", False)

        if not names or not isinstance(names, list):
            raise ValueError("Names must be a non-empty list of parameter names or ARNs")

        response_params = []
        invalid_params = []

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

        data_store = self._read_store()
        all_params = list(data_store.values())
        matching_params = []

        for param in all_params:
            param_name = param["Name"]
            if recursive:
                if param_name.startswith(path):
                    matching_params.append(param)
            else:
                if param_name.startswith(path):
                    remaining = param_name[len(path):].lstrip("/")
                    if "/" not in remaining:
                        matching_params.append(param)

        if param_filters:
            filtered_params = []
            for param in matching_params:
                include = True
                for f in param_filters:
                    key = f.get("Key")
                    option = f.get("Option", "Equals")
                    values = f.get("Values", [])

                    param_value = None
                    if key == "Label":
                        param_value = []
                        for v in param["Versions"].values():
                            param_value.extend(v.get("Labels", []))
                    else:
                        param_value = param.get(key)

                    match = False
                    for v in values:
                        if key == "Label":
                            if option == "Equals" and v in param_value:
                                match = True
                                break
                        else:
                            if option == "Equals" and param_value == v:
                                match = True
                                break
                            elif option == "BeginsWith" and str(param_value).startswith(v):
                                match = True
                                break
                    if not match:
                        include = False
                        break
                if include:
                    filtered_params.append(param)
            matching_params = filtered_params

        matching_params.sort(key=lambda x: x["Name"])

        start_index = int(next_token) if next_token else 0
        end_index = len(matching_params)
        if max_results is not None:
            end_index = min(start_index + max_results, len(matching_params))
            next_token = str(end_index) if end_index < len(matching_params) else None
        else:
            next_token = None

        response_list = []
        for p in matching_params[start_index:end_index]:
            latest_version = max(p["Versions"].keys())
            version_data = p["Versions"][latest_version]

            value = version_data["Value"]
            if p["Type"] == "SecureString" and with_decryption:
                value = base64.b64decode(value.encode()).decode()

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

        data_store = self._read_store()
        param = data_store.get(name)
        if not param:
            raise ValueError(f"Parameter '{name}' not found")

        versions = sorted(param.get("Versions", {}).items(), key=lambda x: x[0], reverse=True)

        start_index = int(next_token) if next_token else 0
        end_index = len(versions)
        if max_results is not None:
            end_index = min(start_index + max_results, len(versions))
            next_token = str(end_index) if end_index < len(versions) else None
        else:
            next_token = None

        response_list = []
        for version_num, version_data in versions[start_index:end_index]:
            value = version_data["Value"]
            if param["Type"] == "SecureString" and with_decryption:
                value = base64.b64decode(value.encode()).decode()

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

        versions = param.get("Versions", {})
        if not versions:
            raise ValueError(f"No versions found for parameter '{name}'")

        if parameter_version is None:
            version = max(int(v) for v in versions.keys())
        else:
            version = int(parameter_version)
            if version not in map(int, versions.keys()):
                raise ValueError(f"Version {version} does not exist for parameter '{name}'")

        invalid_labels = []
        for label in labels:
            if not isinstance(label, str) or not label or not re.match(r'^[a-zA-Z0-9_.-]+$', label):
                invalid_labels.append(label)
                continue

            if label not in versions[f"{version}"].get("Labels", []):
                versions[f"{version}"].setdefault("Labels", []).append(label)

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

        data_store = self._read_store()
        param = data_store.get(name)
        if not param:
            raise ValueError(f"Parameter '{name}' not found")

        versions = param.get("Versions", {})
        if int(parameter_version) not in map(int, versions.keys()):
            raise ValueError(f"Version {parameter_version} does not exist for parameter '{name}'")

        version_data = versions[f"{parameter_version}"]
        existing_labels = version_data.get("Labels", [])

        removed_labels = []
        invalid_labels = []

        for label in labels:
            if label in existing_labels:
                existing_labels.remove(label)
                removed_labels.append(label)
            else:
                invalid_labels.append(label)

        version_data["Labels"] = existing_labels
        versions[parameter_version] = version_data
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

        deleted_params = []
        invalid_params = []

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

        data_store = self._read_store()
        all_params = list(data_store.values())

        filtered_params = []
        for param in all_params:
            include = True
            if param_filters:
                for f in param_filters:
                    key = f.get("Key")
                    option = f.get("Option", "Equals")
                    values = f.get("Values", [])

                    param_value = param.get(key)
                    if param_value is None:
                        include = False
                        break

                    match = False
                    for v in values:
                        if option == "Equals" and param_value == v:
                            match = True
                            break
                        elif option == "BeginsWith" and str(param_value).startswith(v):
                            match = True
                            break
                        elif option == "Contains" and v in str(param_value):
                            match = True
                            break
                    if not match:
                        include = False
                        break
            if include:
                filtered_params.append(param)

        filtered_params.sort(key=lambda x: x["Name"])

        start_index = 0
        if next_token:
            try:
                start_index = int(next_token)
            except ValueError:
                start_index = 0

        end_index = len(filtered_params)
        if max_results is not None:
            end_index = min(start_index + max_results, len(filtered_params))
            next_token = str(end_index) if end_index < len(filtered_params) else None
        else:
            next_token = None

        response_list = []
        for p in filtered_params[start_index:end_index]:
            latest_version = max(p["Versions"].keys())
            version_data = p["Versions"][latest_version]

            response_list.append({
                "Name": p["Name"],
                "ARN": p["ARN"],
                "Type": p["Type"],
                "KeyId": p.get("KeyId"),
                "LastModifiedDate": version_data["LastModifiedDate"],
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
