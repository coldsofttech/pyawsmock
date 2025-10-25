import os
import random
import re
import shutil
import string
import uuid
import warnings
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Dict, Any, List, Tuple

from pyawsmock.mocks.base_mock import MockBase
from pyawsmock.mocks.store_utils import StoreUtils


class MockCodeArtifactValidator:
    TAG_PATTERN = re.compile(r"^[\w\s_.:/=+\-@]+$")
    ASSET_PATTERN = re.compile(r'^[\w~!@\^&()\-\`\_\+\[\]\{\};,\.]+$')
    SEMVER_PATTERN = re.compile(r'^[0-9]+(\.[0-9]+){0,2}([\-a-zA-Z0-9]*)?$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    SUPPORTED_FORMATS = [
        "npm", "pypi", "maven", "nuget", "generic", "ruby", "swift", "cargo"
    ]
    SUPPORTED_ENDPOINT_TYPES = ["dualstack", "ipv4"]
    EXPECTED_EXTENSIONS = {
        "npm": [".tgz"],
        "pypi": [".tar.gz", ".whl"],
        "maven": [".jar", ".pom"],
        "nuget": [".nupkg"],
        "generic": [],
        "ruby": [".gem"],
        "swift": [".zip", ".tar.gz"],
        "cargo": [".crate"],
    }

    @staticmethod
    def _raise_if(condition, message):
        if condition:
            raise ValueError(message)

    @classmethod
    def domain(cls, d: str):
        cls._raise_if(not d, "Domain is required")

    @classmethod
    def repository(cls, r: str):
        cls._raise_if(not r, "Repository is required")

    @classmethod
    def duration(cls, d):
        cls._raise_if(
            int(d) != 0 and not (900 <= int(d) <= 43200),
            f"Duration {d} is not valid"
        )

    @classmethod
    def expected_status(cls, status: str):
        if status:
            cls._raise_if(
                status not in ["Published", "Unfinished", "Unlisted", "Archived", "Disposed", "Deleted"],
                "Invalid ExpectedStatus"
            )

    @classmethod
    def namespace(cls, fmt: str, n: str):
        cls._raise_if(
            fmt in ["maven", "swift", "generic"] and not n,
            f"Namespace is required for format: {fmt}"
        )

    @classmethod
    def repository_format(cls, fmt: str):
        cls._raise_if(not fmt, "Format is required")
        cls._raise_if(
            fmt not in cls.SUPPORTED_FORMATS,
            f"Invalid repository format: {fmt}"
        )

    @classmethod
    def repository_endpoint_type(cls, endpoint: str):
        cls._raise_if(
            endpoint not in cls.SUPPORTED_ENDPOINT_TYPES,
            f"Invalid repository endpoint type: {endpoint}"
        )

    @classmethod
    def asset_name(cls, name: str):
        cls._raise_if(not cls.ASSET_PATTERN.match(name), f"Invalid asset name: {name}")

    @classmethod
    def asset_content(cls, content):
        cls._raise_if(not content, "AssetContent is required")

    @classmethod
    def package(cls, pkg: str):
        cls._raise_if(not pkg, "Package is required")

    @classmethod
    def package_version(cls, version: str):
        cls._raise_if(not cls.SEMVER_PATTERN.match(version), f"Invalid package version: {version}")

    @classmethod
    def sha256(cls, value: str):
        cls._raise_if(not cls.SHA256_PATTERN.match(value), "Invalid SHA256 hash string.")

    @classmethod
    def asset_extension(cls, format_: str, asset_name: str):
        cls._raise_if(
            format_ not in cls.EXPECTED_EXTENSIONS,
            f"Unsupported format type: {format_}"
        )

        # “generic” format accepts any extension
        if format_ == "generic":
            return

        valid_exts = cls.EXPECTED_EXTENSIONS[format_]
        cls._raise_if(
            not any(asset_name.endswith(ext) for ext in valid_exts),
            (f"Invalid asset extension '{asset_name}' for format '{format_}'. "
             f"Expected one of: {', '.join(valid_exts)}")
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
            cls._validate_tag_field("key", key, 128, seen_keys)
            cls._validate_tag_field("value", value, 256)

    @classmethod
    def _validate_tag_field(cls, field_name, value, max_len, seen_keys=None):
        cls._raise_if(not isinstance(value, str), f"Tag {field_name} must be a string")
        if field_name == "key":
            cls._raise_if(value in seen_keys, f"Duplicate Tag Key found: {value}")
            seen_keys.add(value)
        cls._raise_if(not value and field_name == "key", f"Tag {field_name} cannot be empty")
        cls._raise_if(len(value) > max_len, f"Tag {field_name} exceeds {max_len} characters")
        cls._raise_if(value != "" and not cls.TAG_PATTERN.match(value),
                      f"Tag {field_name} contains invalid characters: {value}")


Validator = MockCodeArtifactValidator


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
        return StoreUtils.read_json_gzip(self.store_path)

    def _write_store(self, data):
        StoreUtils.write_json_gzip(self.store_path, data, self.lock_path)

    def _create_path(self, *segments):
        path = os.path.join(*map(str, segments))
        os.makedirs(path, exist_ok=True)
        return path

    def _paginate(self, items: List[Any], max_results: int = None, next_token: str = None) -> Tuple[List[Any], str]:
        start_index = int(next_token) if next_token else 0
        end_index = len(items)
        if max_results is not None:
            end_index = min(start_index + max_results, len(items))
            next_token = str(end_index) if end_index < len(items) else None
        else:
            next_token = None
        return items[start_index:end_index], next_token

    def _get_domain_info(self, domain: str, owner: str = None):
        Validator.domain(domain)
        data_store = self._read_store()
        if domain not in data_store:
            raise ValueError(f"Domain '{domain}' does not exist")
        domain_info = data_store[domain]
        if owner and owner != domain_info["Owner"]:
            raise ValueError(f"Domain '{domain}' does not belong to '{owner}'")
        return domain_info, data_store

    def _get_repo_info(self, domain: str, repo: str, owner: str = None):
        domain_info, data_store = self._get_domain_info(domain, owner)
        Validator.repository(repo)
        repositories = domain_info.setdefault("Repositories", {})
        if repo not in repositories:
            raise ValueError(f"Repository '{repo}' does not exist")
        return repositories[repo], repositories, domain_info, data_store

    def _validate_upstreams(self, upstreams: List[Dict[str, str]], repositories: dict, domain: str):
        for upstream in upstreams:
            upstream_name = upstream.get("repositoryName")
            if not upstream_name or upstream_name not in repositories:
                raise ValueError(f"Repository '{upstream_name}' does not belong to '{domain}'")

    def create_domain(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        tags = kwargs.get("tags", [])
        Validator.domain(domain)
        data_store = self._read_store()
        if domain in data_store:
            raise ValueError(f"Domain {domain} already exists")
        if tags:
            Validator.tags(tags)

        domain_path = Path(self._create_path(self.base_path, "000000000000", domain))
        domain_info = {
            "Name": domain,
            "Owner": "000000000000",
            "Arn": f"arn:mock:codeartifact:{self.region_name}:000000000000:domain/{domain}",
            "Status": "Active",
            "CreatedTime": datetime.now(timezone.utc).isoformat(),
            "EncryptionKey": kwargs.get("encryptionKey"),
            "Repositories": {},
            "RepositoryCount": 0,
            "AssetSizeBytes": 0,
            "S3BucketArn": f"arn:mock:s3:::{domain}-assets",
            "Tags": tags or [],
            "DomainPath": str(domain_path.relative_to(self.base_path)),
        }
        data_store[domain] = domain_info
        self._write_store(data_store)

        return {
            "domain": {
                "name": domain_info["Name"],
                "owner": domain_info["Owner"],
                "arn": domain_info["Arn"],
                "status": domain_info["Status"],
                "createdTime": datetime.fromisoformat(domain_info["CreatedTime"]),
                "encryptionKey": domain_info["EncryptionKey"],
                "repositoryCount": domain_info["RepositoryCount"],
                "assetSizeBytes": domain_info["AssetSizeBytes"],
                "s3BucketArn": domain_info["S3BucketArn"],
            }
        }

    def list_domains(self, **kwargs) -> Dict[str, Any]:
        max_results = kwargs.get("maxResults")
        next_token = kwargs.get("nextToken")
        all_domains = list(self._read_store().values())
        paginated_domains, next_token = self._paginate(all_domains, max_results, next_token)
        response_list = []
        for domain in paginated_domains:
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

        domain_info, data_store = self._get_domain_info(domain, domain_owner)
        Validator.repository(repository)
        if tags:
            Validator.tags(tags)

        repositories = domain_info.setdefault("Repositories", {})
        if repository in repositories:
            raise ValueError(f"Repository {repository} already exists")

        self._validate_upstreams(upstreams, repositories, domain)
        repo_path = os.path.join(self.base_path, domain_info["DomainPath"], repository)
        os.makedirs(repo_path, exist_ok=True)
        repo_info = {
            "Name": repository,
            "AdministratorAccount": "000000000000",
            "Arn": f"arn:mock:codeartifact:{self.region_name}:000000000000:repository/{repository}",
            "Description": description,
            "Upstreams": upstreams,
            "ExternalConnections": [],
            "CreatedTime": datetime.now(timezone.utc).isoformat(),
            "Tags": tags or [],
            "Packages": {},
        }
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
        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)
        repo_path = os.path.join(self.base_path, domain_info["DomainPath"], repository)
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)

        del repositories[repository]
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

    def describe_repository(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)

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
        # domain = kwargs.get("domain")
        # domain_owner = kwargs.get("domainOwner")
        duration = kwargs.get("durationSeconds")
        # domain_info, data_store = self._get_domain_info(domain, domain_owner)
        if duration:
            Validator.duration(duration)
        else:
            duration = 3600
        expiration = datetime.now(timezone.utc) + timedelta(seconds=duration)

        return {
            "authorizationToken": str(uuid.uuid4()),
            "expiration": expiration.isoformat(),
        }

    def get_repository_endpoint(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        domain_owner = kwargs.get("domainOwner")
        repository = kwargs.get("repository")
        format_ = kwargs.get("format")
        endpoint_type = kwargs.get("endpointType")
        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)
        Validator.repository_format(format_)
        if endpoint_type:
            Validator.repository_endpoint_type(endpoint_type)

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

        Validator.repository_format(format_)
        Validator.package(package)
        Validator.package_version(package_version)
        Validator.asset_content(asset_content)
        Validator.asset_name(asset_name)
        Validator.sha256(asset_sha256)
        Validator.namespace(format_, namespace)
        Validator.asset_extension(format_, asset_name)

        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)
        packages = repo_info.setdefault("Packages", {})
        pkg_versions = packages.setdefault(package, {})

        if hasattr(asset_content, "read"):
            content_bytes = asset_content.read()
        elif isinstance(asset_content, bytes):
            content_bytes = asset_content
        else:
            raise ValueError("AssetContent must be bytes or a file-like object")

        if sha256(content_bytes).hexdigest() != asset_sha256:
            raise ValueError("AssetContent does not match")

        package_path = os.path.join(
            self.base_path, domain_info["DomainPath"], repo_info["Name"], package, package_version
        )
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
        repo_info["Packages"] = packages
        data_store[domain]["Repositories"][repository] = repo_info
        self._write_store(data_store)

        return {
            "format": format_,
            "namespace": namespace,
            "package": package,
            "version": package_version,
            "versionRevision": version_revision,
            "status": status,
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

        if publish:
            warnings.warn("publish is not supported in local mock")
        if upstream:
            warnings.warn("upstream is not supported in local mock")

        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)
        packages = repo_info.setdefault("Packages", {})
        summaries = []
        for pkg_name, versions in packages.items():
            if package_prefix and not pkg_name.startswith(package_prefix):
                continue
            latest_version = versions[sorted(versions.keys())[-1]]
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
        end_index = start_index + max_results if max_results else len(summaries)
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

        Validator.repository_format(format_)
        Validator.package(package)
        Validator.namespace(format_, namespace)

        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)
        packages = repo_info.setdefault("Packages", {})
        if package not in packages:
            raise ValueError("Package does not exist")
        versions = packages[package]
        if not versions:
            raise ValueError("Package does not contain any versions")
        latest_version = versions[sorted(versions.keys())[-1]]
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

        Validator.repository_format(format_)
        Validator.package(package)
        Validator.namespace(format_, namespace)
        Validator.expected_status(expected_status)

        if not versions:
            raise ValueError("Versions is required")
        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)
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
                shutil.rmtree(package_path)

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

        Validator.repository_format(format_)
        Validator.package(package)
        Validator.namespace(format_, namespace)

        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)
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
                shutil.rmtree(package_path)

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

        Validator.repository_format(format_)
        Validator.package(package)
        Validator.namespace(format_, namespace)

        repo_info, repositories, domain_info, data_store = self._get_repo_info(domain, repository, domain_owner)
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
