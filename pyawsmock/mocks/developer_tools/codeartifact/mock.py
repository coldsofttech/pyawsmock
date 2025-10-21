import gzip
import json
import os
import random
import re
import shutil
import string
import uuid
import warnings
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from typing import Dict, Any

from pyawsmock.mocks.base_mock import MockBase


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

        key = tag.get("key")
        value = tag.get("value")

        if key is None or value is None:
            raise ValueError("Each tag must contain 'key' and 'value'")

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


def validate_repository_formats(fmt: str):
    if fmt not in ["npm", "pypi", "maven", "nuget", "generic", "ruby", "swift", "cargo"]:
        raise ValueError(f"Invalid repository format: {fmt}")


def validate_repository_endpoint_type(endpoint: str):
    if endpoint not in ["dualstack", "ipv4"]:
        raise ValueError(f"Invalid repository endpoint type: {endpoint}")


def validate_asset_name(name: str):
    allowed_pattern = re.compile(r'^[\w~!@\^&()\-\`\_\+\[\]\{\};,\.]+$')
    if not allowed_pattern.match(name):
        raise ValueError(f"Invalid asset name: {name}")


def validate_package_version(version: str):
    semver_pattern = re.compile(r'^[0-9]+(\.[0-9]+){0,2}([\-a-zA-Z0-9]*)?$')
    if not semver_pattern.match(version):
        raise ValueError(f"Invalid package version: {version}")


def validate_sha256(value: str):
    if not re.fullmatch(r'^[a-fA-F0-9]{64}$', value):
        raise ValueError("Invalid SHA256 hash string.")


def validate_asset_extension(format_: str, asset_name: str):
    expected_ext = {
        "npm": [".tgz"],
        "pypi": [".tar.gz", ".whl"],
        "maven": [".jar", ".pom"],
        "nuget": [".nupkg"],
        "generic": [],  # any allowed
        "ruby": [".gem"],
        "swift": [".zip", ".tar.gz"],
        "cargo": [".crate"],
    }

    if format_ not in expected_ext:
        raise ValueError(f"Unsupported format type: {format_}")

    if format_ == "generic":
        return

    valid_exts = expected_ext[format_]
    if not any(asset_name.endswith(ext) for ext in valid_exts):
        raise ValueError(
            f"Invalid asset extension '{asset_name}' for format '{format_}'. "
            f"Expected one of: {', '.join(valid_exts)}"
        )


class MockCodeArtifact(MockBase):
    _supported_methods = [
        "create_domain",
        "list_domains",
        "create_repository",
        "delete_repository",
        "describe_repository",
        "get_authorization_token",
        "get_repository_endpoint",
        "publish_package_version",
        "list_packages",
        "describe_package",
        "delete_package_versions",
        "delete_package",
        "list_package_versions",
    ]

    def __init__(self, base_path, region_name):
        self.base_path = base_path
        self.region_name = region_name
        self.store_path = base_path / region_name / "codeartifact_repos.json"
        self.data_path = base_path / region_name / "CodeArtifact"
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

    def create_domain(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        enc_key = kwargs.get("encryptionKey")
        tags = kwargs.get("tags", [])

        if not domain:
            raise ValueError("Domain is required")

        if tags:
            validate_tags(tags)

        data_store = self._read_store()
        if domain in data_store:
            raise ValueError(f"Domain {domain} already exists")

        domain_arn = f"arn:mock:codeartifact:{self.region_name}:000000000000:domain/{domain}"
        s3_bucket_arn = f"arn:mock:s3:::{domain}-assets"

        domain_info = {
            "Name": domain,
            "Owner": "000000000000",
            "Arn": domain_arn,
            "Status": "Active",
            "CreatedTime": datetime.now(timezone.utc).isoformat(),
            "EncryptionKey": enc_key,
            "Repositories": {},
            "RepositoryCount": 0,
            "AssetSizeBytes": 0,
            "S3BucketArn": s3_bucket_arn,
            "Tags": tags or [],
        }

        domain_path = self.data_path / "000000000000" / domain
        os.makedirs(domain_path, exist_ok=True)

        domain_info["DomainPath"] = str(domain_path.relative_to(self.base_path))

        data_store[domain] = domain_info
        self._write_store(data_store)

        return {
            "domain": {
                "name": domain_info["Name"],
                "owner": domain_info["Owner"],
                "arn": domain_info["Arn"],
                "status": domain_info["Status"],
                "createdTime": domain_info["CreatedTime"],
                "encryptionKey": domain_info["EncryptionKey"],
                "repositoryCount": domain_info["RepositoryCount"],
                "assetSizeBytes": domain_info["AssetSizeBytes"],
                "s3BucketArn": domain_info["S3BucketArn"],
            }
        }

    def list_domains(self, **kwargs) -> Dict[str, Any]:
        max_results = kwargs.get("maxResults")
        next_token = kwargs.get("nextToken")

        data_store = self._read_store()
        domain_list = list(data_store.values())
        start_index = int(next_token) if next_token else 0
        end_index = len(domain_list)
        if max_results is not None:
            end_index = min(start_index + max_results, len(domain_list))
            next_token = str(end_index) if end_index < len(domain_list) else None
        else:
            next_token = None

        response_list = []
        for domain in domain_list[start_index:end_index]:
            response_list.append({
                "name": domain["Name"],
                "owner": domain["Owner"],
                "arn": domain["Arn"],
                "status": domain["Status"],
                "createdTime": datetime.fromisoformat(domain["CreatedTime"]),
                "encryptionKey": domain["EncryptionKey"],
            })

        return {
            "domains": response_list,
            "nextToken": next_token,
        }

    def create_repository(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        description = kwargs.get("description")
        upstreams = kwargs.get("upstreams", [])
        tags = kwargs.get("tags", [])

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        if tags:
            validate_tags(tags)

        repositories = domain_info.setdefault("Repositories", {})

        if repository in repositories:
            raise ValueError(f"Repository {repository} already exists")

        for upstream in upstreams:
            upstream_name = upstream.get("repositoryName")
            if upstream_name not in repositories:
                raise ValueError(f"Repository {upstream_name} does not belong to {domain}")

        repo_arn = f"arn:mock:codeartifact:{self.region_name}:000000000000:repository/{repository}"
        repo_info = {
            "Name": repository,
            "AdministratorAccount": "000000000000",
            "Arn": repo_arn,
            "Description": description,
            "Upstreams": upstreams,
            "ExternalConnections": [],
            "CreatedTime": datetime.now(timezone.utc).isoformat(),
            "Tags": tags or [],
            "Packages": {},
        }

        repo_path = os.path.join(self.base_path, domain_info["DomainPath"], repository)
        os.makedirs(repo_path, exist_ok=True)

        repositories[repository] = repo_info
        domain_info["Repositories"] = repositories
        domain_info["RepositoryCount"] = len(repositories)
        data_store[domain] = domain_info
        self._write_store(data_store)

        return {
            "repository": {
                "name": repo_info["Name"],
                "administratorAccount": repo_info["AdministratorAccount"],
                "domainName": domain_info["Name"],
                "domainOwner": domain_info["Owner"],
                "arn": repo_info["Arn"],
                "description": repo_info["Description"],
                "upstreams": repo_info["Upstreams"],
                "externalConnections": repo_info["ExternalConnections"],
                "createdTime": datetime.fromisoformat(repo_info["CreatedTime"]),
            }
        }

    def delete_repository(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        repo_bkp = repositories[repository]
        repo_path = os.path.join(self.base_path, domain_info["DomainPath"], repository)
        shutil.rmtree(repo_path)

        del repositories[repository]
        domain_info["RepositoryCount"] = len(repositories)
        data_store[domain] = domain_info
        self._write_store(data_store)

        return {
            "repository": {
                "name": repo_bkp["Name"],
                "administratorAccount": repo_bkp["AdministratorAccount"],
                "domainName": domain_info["Name"],
                "domainOwner": domain_info["Owner"],
                "arn": repo_bkp["Arn"],
                "description": repo_bkp["Description"],
                "upstreams": repo_bkp["Upstreams"],
                "externalConnections": repo_bkp["ExternalConnections"],
                "createdTime": datetime.fromisoformat(repo_bkp["CreatedTime"]),
            }
        }

    def describe_repository(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        repo_info = repositories[repository]

        return {
            "repository": {
                "name": repo_info["Name"],
                "administratorAccount": repo_info["AdministratorAccount"],
                "domainName": domain_info["Name"],
                "domainOwner": domain_info["Owner"],
                "arn": repo_info["Arn"],
                "description": repo_info["Description"],
                "upstreams": repo_info["Upstreams"],
                "externalConnections": repo_info["ExternalConnections"],
                "createdTime": datetime.fromisoformat(repo_info["CreatedTime"]),
            }
        }

    def get_authorization_token(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        duration = kwargs.get("durationSeconds")

        if not domain:
            raise ValueError("Domain is required")

        data_store = self._read_store()
        domain_info = data_store[domain]
        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        if duration:
            if int(duration) != 0 and not (900 <= int(duration) <= 43200):
                raise ValueError(f"Duration {duration} is not valid")

        duration = int(duration) if duration or duration != 0 else 3600  # default mock of one hour
        token = str(uuid.uuid4())
        expiration = datetime.now(timezone.utc) + timedelta(seconds=duration)

        return {
            "authorizationToken": token,
            "expiration": expiration.isoformat(),
        }

    def get_repository_endpoint(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        format_ = kwargs.get("format")
        endpoint_type = kwargs.get("endpointType")

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")
        if not format_:
            raise ValueError("Format is required")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        validate_repository_formats(format_)
        if endpoint_type:
            validate_repository_endpoint_type(endpoint_type)

        warnings.warn("Please note HTTPS endpoints are not supported for local mock.")
        endpoint = (
            f"http://{repository}-{domain}-{domain_info['Owner']}.d.codeartifact."
            f"{self.region_name}.{self._mock_domain}/{format_}/"
        )
        endpoint += f"?endpointType={endpoint_type}"

        return {
            "repositoryEndpoint": endpoint,
        }

    def publish_package_version(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        format_ = kwargs.get("format")
        namespace = kwargs.get("namespace")
        package = kwargs.get("package")
        package_version = kwargs.get("packageVersion")
        asset_content = kwargs.get("assetContent")
        asset_name = kwargs.get("assetName")
        asset_sha256 = kwargs.get("assetSHA256")
        unfinished = kwargs.get("unfinished", False)

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")
        if not format_:
            raise ValueError("Format is required")
        if not package:
            raise ValueError("Package is required")
        if not package_version:
            raise ValueError("PackageVersion is required")
        if not asset_content:
            raise ValueError("AssetContent is required")
        if not asset_name:
            raise ValueError("AssetName is required")
        if not asset_sha256:
            raise ValueError("AssetSha256 is required")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        namespace_required = format_ in ["maven", "swift", "generic"]
        if namespace_required and not namespace:
            raise ValueError(f"Namespace is required for format '{format_}'")

        validate_repository_formats(format_)
        validate_asset_name(asset_name)
        validate_package_version(package_version)
        validate_sha256(asset_sha256)
        validate_asset_extension(format_, asset_name)

        if hasattr(asset_content, "read"):
            content_bytes = asset_content.read()
        elif isinstance(asset_content, bytes):
            content_bytes = asset_content
        else:
            raise ValueError("AssetContent must be bytes or a file-like object")

        computed_sha = sha256(content_bytes).hexdigest()
        if computed_sha != asset_sha256:
            raise ValueError("AssetSha256 does not match")

        repo_info = repositories[repository]
        packages = repo_info.setdefault("Packages", {})
        pkg_versions = packages.setdefault(package, {})

        package_path = os.path.join(self.base_path, domain_info["DomainPath"], repo_info["Name"], package,
                                    package_version)
        os.makedirs(package_path, exist_ok=True)

        asset_path = os.path.join(str(package_path), asset_name)
        with open(asset_path, "wb") as f:
            f.write(content_bytes)

        version_revision = str(uuid.uuid4())
        status = "Unfinished" if unfinished else "Published"
        created_time = datetime.now(timezone.utc).isoformat()
        version_metadata = {
            "Format": format_,
            "Namespace": namespace,
            "Package": package,
            "Version": package_version,
            "VersionRevision": version_revision,
            "Status": status,
            "CreatedTime": created_time,
            "Asset": {
                "Name": asset_name,
                "Size": len(content_bytes),
                "Hashes": {
                    "SHA256": asset_sha256,
                },
            }
        }

        pkg_versions[package_version] = version_metadata
        data_store[domain]["Repositories"][repository]["Packages"] = packages
        self._write_store(data_store)

        return {
            "format": version_metadata["Format"],
            "namespace": version_metadata["Namespace"],
            "package": version_metadata["Package"],
            "version": version_metadata["Version"],
            "versionRevision": version_metadata["VersionRevision"],
            "status": version_metadata["Status"],
            "asset": version_metadata["Asset"],
        }

    def list_packages(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        format_ = kwargs.get("format")
        namespace = kwargs.get("namespace")
        package_prefix = kwargs.get("packagePrefix")
        max_results = kwargs.get("maxResults")
        next_token = kwargs.get("nextToken")
        publish = kwargs.get("publish")
        upstream = kwargs.get("upstream")

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")

        if publish:
            warnings.warn("publish is not supported in local mock")
        if upstream:
            warnings.warn("upstream is not supported in local mock")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        repo_info = repositories[repository]
        packages = repo_info.setdefault("Packages", {})
        summaries = []
        for pkg_name, versions in packages.items():
            if package_prefix and not pkg_name.startswith(package_prefix):
                continue

            version_keys = sorted(versions.keys())
            latest_version = versions[version_keys[-1]]
            pkg_format = latest_version.get("Format")
            pkg_namespace = latest_version.get("Namespace")

            if format_ and pkg_format != format_:
                continue
            if namespace and pkg_namespace and not pkg_namespace.startswith(namespace):
                continue

            summaries.append({
                "format": pkg_format,
                "namespace": pkg_namespace,
                "package": pkg_name,
                "originConfiguration": {  # default for mock
                    "restrictions": {
                        "publish": "ALLOW",
                        "upstream": "ALLOW"
                    }
                }
            })

        summaries.sort(key=lambda x: x["package"])
        start_index = int(next_token) if next_token else 0
        end_index = start_index + max_results
        next_token = str(end_index) if end_index < len(summaries) else None

        return {
            "packages": summaries[start_index:end_index],
            "nextToken": next_token
        }

    def describe_package(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        format_ = kwargs.get("format")
        namespace = kwargs.get("namespace")
        package = kwargs.get("package")

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")
        if not format_:
            raise ValueError("Format is required")
        if not package:
            raise ValueError("Package is required")

        validate_repository_formats(format_)

        namespace_required = format_ in ["maven", "swift", "generic"]
        if namespace_required and not namespace:
            raise ValueError(f"Namespace is required for format '{format_}'")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        repo_info = repositories[repository]
        packages = repo_info.setdefault("Packages", {})
        if package not in packages:
            raise ValueError("Package does not exist")

        versions = packages[package]
        if not versions:
            raise ValueError("Package does not contain any versions")

        version_keys = sorted(versions.keys())
        latest_version = versions[version_keys[-1]]
        pkg_format = latest_version.get("Format")
        pkg_namespace = latest_version.get("Namespace")

        if pkg_format != format_:
            raise ValueError(
                f"Format mismatch: requested '{format}' but package stored as '{pkg_format}'"
            )
        if namespace and pkg_namespace and namespace != pkg_namespace:
            raise ValueError(
                f"Namespace mismatch: requested '{namespace}' but stored '{pkg_namespace}'"
            )

        return {
            "package": {
                "format": pkg_format,
                "namespace": pkg_namespace,
                "name": package,
                "originConfiguration": {  # default for mock
                    "restrictions": {
                        "publish": "ALLOW",
                        "upstream": "ALLOW"
                    }
                }
            }
        }

    def delete_package_versions(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        format_ = kwargs.get("format")
        namespace = kwargs.get("namespace")
        package = kwargs.get("package")
        versions = kwargs.get("versions")
        expected_status = kwargs.get("expectedStatus")

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")
        if not format_:
            raise ValueError("Format is required")
        if not package:
            raise ValueError("Package is required")
        if not versions:
            raise ValueError("Versions is required")

        validate_repository_formats(format_)

        if expected_status:
            if expected_status not in ["Published", "Unfinished", "Unlisted", "Archived", "Disposed", "Deleted"]:
                raise ValueError("Invalid expectedStatus")

        namespace_required = format_ in ["maven", "swift", "generic"]
        if namespace_required and not namespace:
            raise ValueError(f"Namespace is required for format '{format_}'")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        repo_info = repositories[repository]
        packages = repo_info.setdefault("Packages", {})
        pkg_versions = packages.get(package, {})

        successful_versions = {}
        failed_versions = {}

        for ver in versions:
            if ver not in pkg_versions:
                failed_versions[ver] = {
                    "errorCode": "NOT_FOUND",
                    "errorMessage": f"Version {ver} does not exist"
                }
                continue

            current_version = pkg_versions[ver]

            if expected_status and current_version.get("Status") != expected_status:
                failed_versions[ver] = {
                    "errorCode": "MISMATCHED_STATUS",
                    "errorMessage": f"Expected status {expected_status}, found {current_version.get('Status')}"
                }
                continue

            if random.random() < 0.05:  # 5% chance to fail deletion
                failed_versions[ver] = {
                    "errorCode": "NOT_ALLOWED",
                    "errorMessage": f"Cannot delete version {ver} due to restrictions"
                }
                continue

            new_revision = "rev-" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            current_version.update({
                "Status": "Deleted",
                "VersionRevision": new_revision,
                "DeletedTime": datetime.now(timezone.utc).isoformat()
            })
            successful_versions[ver] = {
                "revision": new_revision,
                "status": "Deleted"
            }

            asset_name = current_version.get("Asset", {}).get("Name")
            package_path = os.path.join(
                self.base_path,
                domain_info["DomainPath"],
                repo_info["Name"],
                package,
                ver
            )
            asset_path = os.path.join(str(package_path), asset_name) if asset_name else None
            if asset_path and os.path.exists(asset_path):
                os.remove(asset_path)

            if os.path.exists(package_path) and not os.listdir(str(package_path)):
                os.rmdir(package_path)

        packages[package] = pkg_versions
        repo_info["Packages"] = packages
        data_store[domain]["Repositories"][repository] = repo_info
        self._write_store(data_store)

        return {
            "successfulVersions": successful_versions,
            "failedVersions": failed_versions
        }

    def delete_package(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        format_ = kwargs.get("format")
        namespace = kwargs.get("namespace")
        package = kwargs.get("package")

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")
        if not format_:
            raise ValueError("Format is required")
        if not package:
            raise ValueError("Package is required")

        validate_repository_formats(format_)

        namespace_required = format_ in ["maven", "swift", "generic"]
        if namespace_required and not namespace:
            raise ValueError(f"Namespace is required for format '{format_}'")

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        repo_info = repositories[repository]
        packages = repo_info.setdefault("Packages", {})
        if package not in packages:
            raise ValueError("Package does not exist")

        package_versions = packages[package]
        for version, version_info in package_versions.items():
            asset_name = version_info.get("Asset", {}).get("Name")
            package_path = os.path.join(
                self.base_path,
                domain_info["DomainPath"],
                repo_info["Name"],
                package
            )
            asset_path = os.path.join(str(package_path), version, asset_name) if asset_name else None
            if asset_path and os.path.exists(asset_path):
                os.remove(asset_path)

            if os.path.exists(package_path) and not os.listdir(str(package_path)):
                os.rmdir(package_path)

        del packages[package]
        repo_info["Packages"] = packages
        data_store[domain]["Repositories"][repository] = repo_info
        self._write_store(data_store)

        return {
            "deletedPackage": {
                "format": format_,
                "namespace": namespace if namespace else "",
                "package": package,
                "originConfiguration": {  # default for mock
                    "restrictions": {
                        "publish": "ALLOW",
                        "upstream": "ALLOW"
                    }
                }
            }
        }

    def list_package_versions(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        format_ = kwargs.get("format")
        namespace = kwargs.get("namespace")
        package = kwargs.get("package")
        status_filter = kwargs.get("status")
        max_results = kwargs.get("maxResults")
        next_token = kwargs.get("nextToken")
        origin_type_filter = kwargs.get("originType")

        if not domain:
            raise ValueError("Domain is required")
        if not repository:
            raise ValueError("Repository is required")
        if not format_:
            raise ValueError("Format is required")
        if not package:
            raise ValueError("Package is required")

        namespace_required = format_ in ["maven", "swift", "generic"]
        if namespace_required and not namespace:
            raise ValueError(f"Namespace is required for format '{format_}'")

        validate_repository_formats(format_)

        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError("Domain does not exist")

        domain_info = data_store[domain]
        if domain_owner and domain_owner != domain_info["Owner"]:
            raise ValueError(f"Domain {domain} does not belong to {domain_owner}")

        repositories = domain_info.setdefault("Repositories", {})
        if repository not in repositories:
            raise ValueError("Repository does not exist")

        repo_info = repositories[repository]
        packages = repo_info.setdefault("Packages", {})
        if package not in packages:
            raise ValueError(f"Package '{package}' does not exist in repository '{repository}'")

        package_versions = packages[package]
        versions_list = []

        for ver, ver_info in package_versions.items():
            if status_filter and ver_info["Status"] != status_filter:
                continue
            origin_type = ver_info.get("Origin", {}).get("OriginType", "INTERNAL")
            if origin_type_filter and origin_type != origin_type_filter:
                continue

            versions_list.append({
                "version": ver_info["Version"],
                "revision": ver_info["VersionRevision"],
                "status": ver_info["Status"],
                "origin": {
                    "domainEntryPoint": {
                        "repositoryName": repository,
                        "externalConnectionName": ver_info.get("Origin", {}).get("ExternalConnectionName", "")
                    },
                    "originType": origin_type
                }
            })

        versions_list.sort(key=lambda x: package_versions[x["version"]]["CreatedTime"], reverse=True)

        start_index = int(next_token) if next_token else 0
        end_index = len(versions_list)
        if max_results:
            end_index = min(start_index + max_results, len(versions_list))
            next_token = str(end_index) if end_index < len(versions_list) else None
        else:
            next_token = None

        paged_versions = versions_list[start_index:end_index]
        default_display_version = paged_versions[0]["version"] if paged_versions else None

        return {
            "defaultDisplayVersion": default_display_version,
            "format": format_,
            "namespace": namespace if namespace else "",
            "package": package,
            "versions": paged_versions,
            "nextToken": next_token
        }
