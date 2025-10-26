import base64
import binascii
from datetime import datetime

import pytest

from pyawsmock.mocks.management_and_governance.ssm.mock import MockSSM

pytestmark = pytest.mark.order(3)


@pytest.fixture
def temp_store(tmp_path):
    region_dir = tmp_path / "mock-region"
    region_dir.mkdir()
    return region_dir


@pytest.fixture
def ssm(temp_store):
    return MockSSM(base_path=temp_store, region_name="mock-region")


@pytest.fixture
def ssm_with_params(tmp_path):
    ssm = MockSSM(base_path=tmp_path, region_name="mock-region")

    ssm.put_parameter(Name="/app/config/db", Value="postgres", Type="String")

    ssm.put_parameter(Name="/app/config/api", Value="enabled", Type="String", Tier="Advanced")

    ssm.put_parameter(Name="/app/versioned", Value="v1", Type="String")
    ssm.put_parameter(Name="/app/versioned", Value="v2", Type="String", Overwrite=True)

    key_id = "arn:mock:kms:local:000000000000:key/123e4567-e89b-12d3-a456-426614174000"
    ssm.put_parameter(Name="/secure/secret", Value="sensitive", Type="SecureString", KeyId=key_id)

    # Add a label to v1 manually (simulate label)
    data = ssm._read_store()
    data["/app/versioned"]["Versions"]["1"]["Labels"] = ["stable"]
    ssm._write_store(data)

    return ssm


@pytest.fixture
def ssm_with_path_params(tmp_path):
    ssm = MockSSM(base_path=tmp_path, region_name="mock-region")

    # Standard parameters
    ssm.put_parameter(Name="/app/config/db", Value="postgres", Type="String")
    ssm.put_parameter(Name="/app/config/api", Value="enabled", Type="String")

    # Nested parameters for recursive test
    ssm.put_parameter(Name="/app/config/db/replica", Value="replica1", Type="String")

    # Advanced tier
    ssm.put_parameter(Name="/app/advanced/feature", Value="on", Type="String", Tier="Advanced")

    # SecureString
    ssm.put_parameter(Name="/app/secure/secret", Value="mysecret", Type="SecureString", KeyId="alias/mock-key")

    # Parameter with labels
    ssm.put_parameter(Name="/app/labeled", Value="v1", Type="String")
    ssm.label_parameter_version(Name="/app/labeled", Labels=["prod", "v1"])

    return ssm


@pytest.fixture
def ssm_with_history_params(tmp_path):
    ssm = MockSSM(base_path=tmp_path, region_name="mock-region")

    # Create a parameter with multiple versions
    ssm.put_parameter(Name="/app/config/db", Value="v1", Type="String")
    ssm.put_parameter(Name="/app/config/db", Value="v2", Type="String", Overwrite=True)
    ssm.put_parameter(Name="/app/config/db", Value="v3", Type="String", Overwrite=True)

    # SecureString parameter
    ssm.put_parameter(Name="/app/secure/secret", Value="secret1", Type="SecureString", KeyId="alias/mock-key")
    ssm.put_parameter(Name="/app/secure/secret", Value="secret2", Type="SecureString", KeyId="alias/mock-key",
                      Overwrite=True)

    return ssm


@pytest.fixture
def ssm_with_versioned_param(tmp_path):
    ssm = MockSSM(tmp_path, "mock-region")
    ssm.put_parameter(Name="/app/config/db", Value="v1")
    ssm.put_parameter(Name="/app/config/db", Value="v2", Overwrite=True)
    return ssm


@pytest.fixture
def ssm_with_labeled_param(tmp_path):
    ssm = MockSSM(tmp_path, "mock-region")
    ssm.put_parameter(Name="/app/config/db", Value="postgres")
    # Add initial labels
    ssm.label_parameter_version(Name="/app/config/db", Labels=["Prod", "Test"])
    return ssm


@pytest.fixture
def ssm_with_versioned_labels(tmp_path):
    ssm = MockSSM(tmp_path, "mock-region")
    ssm.put_parameter(Name="/app/config/db", Value="v1")
    ssm.put_parameter(Name="/app/config/db", Value="v2", Overwrite=True)
    # Label version 1
    ssm.label_parameter_version(Name="/app/config/db", ParameterVersion=1, Labels=["Old"])
    # Label version 2
    ssm.label_parameter_version(Name="/app/config/db", ParameterVersion=2, Labels=["Latest"])
    return ssm


def test_put_parameter_success_basic(ssm):
    resp = ssm.put_parameter(Name="/app/config/db", Value="postgres", Type="String")
    assert resp["Version"] == 1
    assert resp["Tier"] == "Standard"

    data = ssm._read_store()
    assert "/app/config/db" in data
    assert data["/app/config/db"]["Type"] == "String"
    assert data["/app/config/db"]["Versions"]["1"]["Value"] == "postgres"


def test_put_parameter_updates_version(ssm):
    ssm.put_parameter(Name="/test/param", Value="v1", Type="String")
    resp = ssm.put_parameter(Name="/test/param", Value="v2", Type="String", Overwrite=True)

    data = ssm._read_store()["/test/param"]
    assert resp["Version"] == 2
    assert len(data["Versions"]) == 2
    assert data["Versions"]["2"]["Value"] == "v2"


def test_put_parameter_with_tier_advanced(ssm):
    resp = ssm.put_parameter(Name="/tier/test", Value="data", Tier="Advanced")
    assert resp["Tier"] == "Advanced"


def test_put_parameter_secure_string_with_keyid(ssm):
    key_id = "arn:mock:kms:local:000000000000:key/123e4567-e89b-12d3-a456-426614174000"
    resp = ssm.put_parameter(Name="/secure/password", Value="secret", Type="SecureString", KeyId=key_id)
    assert resp["Version"] == 1

    store = ssm._read_store()
    encoded_val = store["/secure/password"]["Versions"]["1"]["Value"]
    decoded_val = base64.b64decode(encoded_val.encode()).decode()
    assert decoded_val == "secret"


def test_put_parameter_secure_string_without_keyid(ssm):
    with pytest.raises(ValueError, match="KMS Key Id is required"):
        ssm.put_parameter(Name="/secure/missingkey", Value="secret", Type="SecureString")


def test_put_parameter_invalid_kms_keyid_format(ssm):
    with pytest.raises(ValueError, match="Invalid KeyId format"):
        ssm.put_parameter(Name="/secure/invalid", Value="data", Type="SecureString", KeyId="bad-key-format")


@pytest.mark.parametrize("name,value", [
    (None, "abc"),
    ("/path", None),
    (None, None),
])
def test_put_parameter_missing_required(ssm, name, value):
    with pytest.raises(ValueError, match="required"):
        ssm.put_parameter(Name=name, Value=value)


@pytest.mark.parametrize("bad_name", [
    "/aws/config",
    "aws_test",
    "/ssm/param",
    "ssm/value",
])
def test_put_parameter_invalid_name_prefix(ssm, bad_name):
    with pytest.raises(ValueError, match="cannot start with"):
        ssm.put_parameter(Name=bad_name, Value="ok")


def test_put_parameter_invalid_name_characters(ssm):
    with pytest.raises(ValueError, match="Invalid characters"):
        ssm.put_parameter(Name="/bad!name", Value="ok")


def test_put_parameter_exceed_hierarchy_depth(ssm):
    deep_path = "/" + "/".join(f"lvl{i}" for i in range(16))
    with pytest.raises(ValueError, match="hierarchy exceeds"):
        ssm.put_parameter(Name=deep_path, Value="ok")


def test_put_parameter_value_too_large_standard(ssm):
    big_value = "x" * (4096 + 1)
    with pytest.raises(ValueError, match="exceeds 4KB"):
        ssm.put_parameter(Name="/big/value", Value=big_value, Tier="Standard")


def test_put_parameter_allowed_pattern_fail(ssm):
    pattern = r"^\d+$"
    with pytest.raises(ValueError, match="AllowedPattern"):
        ssm.put_parameter(Name="/pattern/test", Value="notdigits", AllowedPattern=pattern)


def test_put_parameter_tags_success(ssm):
    tags = [{"Key": "env", "Value": "prod"}, {"Key": "team", "Value": "core"}]
    ssm.put_parameter(Name="/tagged/param", Value="tagged", Tags=tags)
    data = ssm._read_store()["/tagged/param"]
    assert data["Tags"] == tags


@pytest.mark.parametrize("tags,err", [
    ([{"Key": None, "Value": "v"}], "must contain 'Key'"),
    ([{"Key": "a", "Value": None}], "must contain 'Key'"),
    ("notalist", "Tags must be a list"),
    ([{"Key": "bad key!", "Value": "ok"}], "invalid characters"),
])
def test_put_parameter_invalid_tags(ssm, tags, err):
    with pytest.raises(ValueError, match=err):
        ssm.put_parameter(Name="/bad/tags", Value="ok", Tags=tags)


def test_put_parameter_invalid_type(ssm):
    with pytest.raises(ValueError, match="Invalid type"):
        ssm.put_parameter(Name="/param", Value="v", Type="WrongType")


def test_put_parameter_invalid_tier(ssm):
    with pytest.raises(ValueError, match="Invalid tier"):
        ssm.put_parameter(Name="/param", Value="v", Tier="Ultra")


def test_put_parameter_invalid_datatype(ssm):
    with pytest.raises(ValueError, match="Invalid data type"):
        ssm.put_parameter(Name="/param", Value="v", DataType="wrong:type")


def test_put_parameter_duplicate_tag_keys(ssm):
    tags = [{"Key": "env", "Value": "prod"}, {"Key": "env", "Value": "dev"}]
    with pytest.raises(ValueError, match="Duplicate Tag Key"):
        ssm.put_parameter(Name="/dup/tags", Value="v", Tags=tags)


def test_put_parameter_store_persistence(ssm):
    ssm.put_parameter(Name="/persist/test", Value="one", Type="String")
    new_ssm = MockSSM(base_path=ssm.store_path.parent.parent, region_name="mock-region")
    data = new_ssm._read_store()
    assert "/persist/test" in data


def test_get_parameter_basic_success(ssm_with_params):
    resp = ssm_with_params.get_parameter(Name="/app/config/db")
    param = resp["Parameter"]

    assert param["Name"] == "/app/config/db"
    assert param["Value"] == "postgres"
    assert param["Type"] == "String"
    assert isinstance(param["LastModifiedDate"], datetime)


def test_get_parameter_latest_version(ssm_with_params):
    resp = ssm_with_params.get_parameter(Name="/app/versioned")
    param = resp["Parameter"]

    assert param["Version"] == 2  # should return latest
    assert param["Value"] == "v2"


def test_get_parameter_by_version_selector(ssm_with_params):
    resp = ssm_with_params.get_parameter(Name="/app/versioned:1")
    assert resp["Parameter"]["Value"] == "v1"


def test_get_parameter_by_label_selector(ssm_with_params):
    resp = ssm_with_params.get_parameter(Name="/app/versioned:stable")
    assert resp["Parameter"]["Value"] == "v1"


def test_get_parameter_securestring_without_decryption(ssm_with_params):
    resp = ssm_with_params.get_parameter(Name="/secure/secret", WithDecryption=False)
    value = resp["Parameter"]["Value"]

    # should still be base64 encoded
    assert value != "sensitive"
    assert base64.b64decode(value.encode()).decode() == "sensitive"


def test_get_parameter_securestring_with_decryption(ssm_with_params):
    resp = ssm_with_params.get_parameter(Name="/secure/secret", WithDecryption=True)
    assert resp["Parameter"]["Value"] == "sensitive"


def test_get_parameter_securestring_decode_failure(ssm_with_params):
    data = ssm_with_params._read_store()
    data["/secure/secret"]["Versions"]["1"]["Value"] = "not-base64!"
    ssm_with_params._write_store(data)

    with pytest.raises(binascii.Error, match="Invalid base64-encoded string"):
        ssm_with_params.get_parameter(Name="/secure/secret", WithDecryption=True)


def test_get_parameter_missing_name(ssm_with_params):
    with pytest.raises(ValueError, match="required"):
        ssm_with_params.get_parameter(Name=None)


def test_get_parameter_not_found(ssm_with_params):
    with pytest.raises(ValueError, match="not found"):
        ssm_with_params.get_parameter(Name="/nonexistent/param")


def test_get_parameter_invalid_version_selector(ssm_with_params):
    with pytest.raises(ValueError, match="Version 99 not found"):
        ssm_with_params.get_parameter(Name="/app/versioned:99")


def test_get_parameter_invalid_label_selector(ssm_with_params):
    with pytest.raises(ValueError, match="Label notfound not found"):
        ssm_with_params.get_parameter(Name="/app/versioned:notfound")


def test_get_parameter_with_arn_success(ssm_with_params):
    arn = "arn:mock:ssm:mock-region:000000000000:parameter/app/config/db"
    resp = ssm_with_params.get_parameter(Name=arn)
    assert resp["Parameter"]["Value"] == "postgres"


def test_get_parameter_with_invalid_arn(ssm_with_params):
    bad_arn = "arn:mock:ssm:mock-region:parameter/app/config/db"
    with pytest.raises(ValueError, match="not found"):
        ssm_with_params.get_parameter(Name=bad_arn)


def test_get_parameter_response_metadata(ssm_with_params):
    resp = ssm_with_params.get_parameter(Name="/app/config/db")
    param = resp["Parameter"]

    assert set(param.keys()) == {
        "Name", "Type", "Value", "Version", "Selector", "SourceResult",
        "LastModifiedDate", "ARN", "DataType"
    }
    assert param["ARN"].startswith("arn:mock:ssm:mock-region:")


def test_get_parameter_selector_case_sensitive(ssm_with_params):
    # label "stable" exists; "Stable" does not
    with pytest.raises(ValueError, match="Label Stable not found"):
        ssm_with_params.get_parameter(Name="/app/versioned:Stable")


def test_get_parameter_securestring_decoding_only_when_requested(ssm_with_params):
    encoded_value = ssm_with_params.get_parameter(Name="/secure/secret")["Parameter"]["Value"]
    decoded_value = ssm_with_params.get_parameter(Name="/secure/secret", WithDecryption=True)["Parameter"]["Value"]
    assert encoded_value != decoded_value


def test_get_parameters_basic_success(ssm_with_params):
    names = ["/app/config/db", "/app/versioned"]
    resp = ssm_with_params.get_parameters(Names=names)
    assert "Parameters" in resp
    assert "InvalidParameters" in resp
    assert len(resp["Parameters"]) == 2
    assert resp["InvalidParameters"] == []

    # Ensure sorted by name
    param_names = [p["Name"] for p in resp["Parameters"]]
    assert param_names == sorted(param_names)


def test_get_parameters_with_arns(ssm_with_params):
    names = [
        "arn:mock:ssm:mock-region:000000000000:parameter/app/config/db",
        "arn:mock:ssm:mock-region:000000000000:parameter/app/versioned"
    ]
    resp = ssm_with_params.get_parameters(Names=names)
    assert len(resp["Parameters"]) == 2
    assert resp["InvalidParameters"] == []


def test_get_parameters_with_invalid(ssm_with_params):
    names = ["/app/config/db", "/nonexistent", "/app/versioned"]
    resp = ssm_with_params.get_parameters(Names=names)

    assert len(resp["Parameters"]) == 2
    assert "/nonexistent" in resp["InvalidParameters"]


def test_get_parameters_securestring_decryption(ssm_with_params):
    names = ["/secure/secret"]
    resp = ssm_with_params.get_parameters(Names=names, WithDecryption=True)

    param = resp["Parameters"][0]
    assert param["Value"] == "sensitive"


def test_get_parameters_securestring_no_decryption(ssm_with_params):
    names = ["/secure/secret"]
    resp = ssm_with_params.get_parameters(Names=names, WithDecryption=False)

    param = resp["Parameters"][0]
    assert param["Value"] != "sensitive"
    assert base64.b64decode(param["Value"].encode()).decode() == "sensitive"


def test_get_parameters_mixed_valid_invalid(ssm_with_params):
    names = ["/app/config/db", "/app/versioned", "/missing", "/also_missing"]
    resp = ssm_with_params.get_parameters(Names=names)

    assert len(resp["Parameters"]) == 2
    assert set(resp["InvalidParameters"]) == {"/missing", "/also_missing"}


@pytest.mark.parametrize("names", [None, [], "notalist"])
def test_get_parameters_invalid_input(ssm_with_params, names):
    with pytest.raises(ValueError, match="Names must be a non-empty list"):
        ssm_with_params.get_parameters(Names=names)


def test_get_parameters_sorting(ssm_with_params):
    names = ["/app/versioned", "/app/config/db"]
    resp = ssm_with_params.get_parameters(Names=names)
    param_names = [p["Name"] for p in resp["Parameters"]]
    assert param_names == sorted(param_names)


def test_get_parameters_metadata(ssm_with_params):
    resp = ssm_with_params.get_parameters(Names=["/app/config/db"])
    param = resp["Parameters"][0]
    assert set(param.keys()) == {
        "Name", "Type", "Value", "Version", "Selector",
        "SourceResult", "LastModifiedDate", "ARN", "DataType"
    }


def test_get_parameters_all_invalid(ssm_with_params):
    names = ["/missing1", "/missing2"]
    resp = ssm_with_params.get_parameters(Names=names)
    assert resp["Parameters"] == []
    assert set(resp["InvalidParameters"]) == {"/missing1", "/missing2"}


def test_delete_parameter_success(ssm_with_params):
    resp = ssm_with_params.delete_parameter(Name="/app/config/db")
    assert resp == {}  # delete_parameter returns empty dict

    # Ensure parameter is removed from store
    data_store = ssm_with_params._read_store()
    assert "/app/config/db" not in data_store


def test_delete_parameter_not_found(ssm_with_params):
    with pytest.raises(ValueError, match="not found"):
        ssm_with_params.delete_parameter(Name="/nonexistent/param")


def test_delete_parameter_missing_name(ssm_with_params):
    with pytest.raises(ValueError, match="Name is required"):
        ssm_with_params.delete_parameter(Name=None)


def test_delete_parameter_twice(ssm_with_params):
    # First deletion succeeds
    resp = ssm_with_params.delete_parameter(Name="/app/versioned")
    assert resp == {}

    # Second deletion should fail
    with pytest.raises(ValueError, match="not found"):
        ssm_with_params.delete_parameter(Name="/app/versioned")


def test_delete_parameter_does_not_affect_others(ssm_with_params):
    # Delete one parameter
    ssm_with_params.delete_parameter(Name="/app/config/db")

    # Ensure other parameter still exists
    data_store = ssm_with_params._read_store()
    assert "/app/versioned" in data_store


def test_delete_parameters_all_valid(ssm_with_params):
    names = ["/app/config/db", "/app/versioned"]
    resp = ssm_with_params.delete_parameters(Names=names)

    assert set(resp["DeletedParameters"]) == set(names)
    assert resp["InvalidParameters"] == []

    # Ensure parameters are removed
    data_store = ssm_with_params._read_store()
    for name in names:
        assert name not in data_store


def test_delete_parameters_some_invalid(ssm_with_params):
    names = ["/app/config/db", "/nonexistent", "/app/versioned", "/missing"]
    resp = ssm_with_params.delete_parameters(Names=names)

    assert set(resp["DeletedParameters"]) == {"/app/config/db", "/app/versioned"}
    assert set(resp["InvalidParameters"]) == {"/nonexistent", "/missing"}

    data_store = ssm_with_params._read_store()
    for deleted in ["/app/config/db", "/app/versioned"]:
        assert deleted not in data_store


def test_delete_parameters_all_invalid(ssm_with_params):
    names = ["/missing1", "/missing2"]
    resp = ssm_with_params.delete_parameters(Names=names)

    assert resp["DeletedParameters"] == []
    assert set(resp["InvalidParameters"]) == {"/missing1", "/missing2"}

    # Ensure existing parameters remain
    data_store = ssm_with_params._read_store()
    assert "/app/config/db" in data_store
    assert "/app/versioned" in data_store


@pytest.mark.parametrize("names", [None, [], "notalist"])
def test_delete_parameters_invalid_input(ssm_with_params, names):
    with pytest.raises(ValueError, match="Names must be a non-empty list"):
        ssm_with_params.delete_parameters(Names=names)


def test_delete_parameters_partial_impact(ssm_with_params):
    # Only delete secure parameter
    resp = ssm_with_params.delete_parameters(Names=["/secure/secret"])
    assert resp["DeletedParameters"] == ["/secure/secret"]
    assert resp["InvalidParameters"] == []

    # Ensure others remain
    data_store = ssm_with_params._read_store()
    assert "/app/config/db" in data_store
    assert "/app/versioned" in data_store


def test_delete_parameters_duplicate_names(ssm_with_params):
    names = ["/app/config/db", "/app/config/db"]
    resp = ssm_with_params.delete_parameters(Names=names)

    # First occurrence deleted, second treated as invalid
    assert resp["DeletedParameters"] == ["/app/config/db"]
    assert resp["InvalidParameters"] == ["/app/config/db"]


def test_describe_parameters_no_filters(ssm_with_params):
    resp = ssm_with_params.describe_parameters()
    assert len(resp["Parameters"]) == 4
    for p in resp["Parameters"]:
        assert "Name" in p
        assert "ARN" in p
        assert "Type" in p
        assert "Version" in p


def test_describe_parameters_with_equals_filter(ssm_with_params):
    filters = [{"Key": "Tier", "Option": "Equals", "Values": ["Advanced"]}]
    resp = ssm_with_params.describe_parameters(ParameterFilters=filters)
    assert len(resp["Parameters"]) == 1
    assert resp["Parameters"][0]["Name"] == "/app/config/api"


def test_describe_parameters_with_beginswith_filter(ssm_with_params):
    filters = [{"Key": "Name", "Option": "BeginsWith", "Values": ["/app/config"]}]
    resp = ssm_with_params.describe_parameters(ParameterFilters=filters)
    assert len(resp["Parameters"]) == 2
    names = [p["Name"] for p in resp["Parameters"]]
    assert "/app/config/db" in names
    assert "/app/config/api" in names


def test_describe_parameters_with_contains_filter(ssm_with_params):
    filters = [{"Key": "Name", "Option": "Contains", "Values": ["versioned"]}]
    resp = ssm_with_params.describe_parameters(ParameterFilters=filters)
    assert len(resp["Parameters"]) == 1
    assert resp["Parameters"][0]["Name"] == "/app/versioned"


def test_describe_parameters_with_max_results(ssm_with_params):
    resp = ssm_with_params.describe_parameters(MaxResults=2)
    assert len(resp["Parameters"]) == 2
    assert resp["NextToken"] is not None


def test_describe_parameters_with_next_token(ssm_with_params):
    first_page = ssm_with_params.describe_parameters(MaxResults=2)
    second_page = ssm_with_params.describe_parameters(MaxResults=2, NextToken=first_page["NextToken"])
    assert len(second_page["Parameters"]) == 2
    assert second_page["NextToken"] is None


def test_describe_parameters_shared_warning(ssm_with_params):
    with pytest.warns(UserWarning, match="Shared is not supported"):
        resp = ssm_with_params.describe_parameters(Shared=True)
    # also verify that parameters are still returned
    assert isinstance(resp["Parameters"], list)


def test_describe_parameters_filter_no_match(ssm_with_params):
    filters = [{"Key": "Tier", "Option": "Equals", "Values": ["NonExistentTier"]}]
    resp = ssm_with_params.describe_parameters(ParameterFilters=filters)
    assert resp["Parameters"] == []
    assert resp["NextToken"] is None


def test_describe_parameters_invalid_next_token(ssm_with_params):
    # passing a non-integer NextToken should default to 0
    resp = ssm_with_params.describe_parameters(NextToken="invalid")
    assert len(resp["Parameters"]) == 4
    assert resp["NextToken"] is None


def test_describe_parameters_empty_store(tmp_path):
    ssm = MockSSM(base_path=tmp_path, region_name="mock-region")
    resp = ssm.describe_parameters()
    assert resp["Parameters"] == []
    assert resp["NextToken"] is None


def test_get_parameters_by_path_basic(ssm_with_path_params):
    resp = ssm_with_path_params.get_parameters_by_path(Path="/app/config", Recursive=False)
    names = [p["Name"] for p in resp["Parameters"]]
    assert "/app/config/db" in names
    assert "/app/config/api" in names
    assert "/app/config/db/replica" not in names


def test_get_parameters_by_path_recursive(ssm_with_path_params):
    resp = ssm_with_path_params.get_parameters_by_path(Path="/app/config", Recursive=True)
    names = [p["Name"] for p in resp["Parameters"]]
    assert "/app/config/db" in names
    assert "/app/config/api" in names
    assert "/app/config/db/replica" in names


def test_get_parameters_by_path_with_max_results(ssm_with_path_params):
    resp = ssm_with_path_params.get_parameters_by_path(Path="/app", Recursive=True, MaxResults=2)
    assert len(resp["Parameters"]) == 2
    assert resp["NextToken"] is not None


def test_get_parameters_by_path_with_next_token(ssm_with_path_params):
    first_page = ssm_with_path_params.get_parameters_by_path(Path="/app", Recursive=True, MaxResults=2)
    second_page = ssm_with_path_params.get_parameters_by_path(Path="/app", Recursive=True, MaxResults=2,
                                                              NextToken=first_page["NextToken"])
    assert len(second_page["Parameters"]) >= 1
    # NextToken can be None if end reached
    assert "NextToken" in second_page


def test_get_parameters_by_path_with_decryption(ssm_with_path_params):
    resp = ssm_with_path_params.get_parameters_by_path(Path="/app/secure", Recursive=True, WithDecryption=True)
    param = resp["Parameters"][0]
    assert param["Value"] == "mysecret"


def test_get_parameters_by_path_with_label_filter(ssm_with_path_params):
    filters = [{"Key": "Label", "Option": "Equals", "Values": ["prod"]}]
    resp = ssm_with_path_params.get_parameters_by_path(Path="/app", Recursive=True, ParameterFilters=filters)
    names = [p["Name"] for p in resp["Parameters"]]
    assert "/app/labeled" in names
    # Only the labeled parameter should match
    assert len(names) == 1


def test_get_parameters_by_path_missing_path(ssm_with_path_params):
    with pytest.raises(ValueError, match="Path must start with '/'"):
        ssm_with_path_params.get_parameters_by_path(Path=None)


def test_get_parameters_by_path_invalid_path(ssm_with_path_params):
    with pytest.raises(ValueError, match="Path must start with '/'"):
        ssm_with_path_params.get_parameters_by_path(Path="invalid/path")


def test_get_parameters_by_path_no_match(ssm_with_path_params):
    resp = ssm_with_path_params.get_parameters_by_path(Path="/nonexistent", Recursive=True)
    assert resp["Parameters"] == []
    assert resp["NextToken"] is None


def test_get_parameters_by_path_securestring_no_decryption(ssm_with_path_params):
    resp = ssm_with_path_params.get_parameters_by_path(Path="/app/secure", Recursive=True, WithDecryption=False)
    param = resp["Parameters"][0]
    # Value should be base64 encoded
    decoded = base64.b64decode(param["Value"].encode()).decode()
    assert decoded == "mysecret"


def test_get_parameter_history_basic(ssm_with_history_params):
    resp = ssm_with_history_params.get_parameter_history(Name="/app/config/db")
    versions = [int(p["Version"]) for p in resp["Parameters"]]
    assert versions == [3, 2, 1]  # descending order


def test_get_parameter_history_max_results(ssm_with_history_params):
    resp = ssm_with_history_params.get_parameter_history(Name="/app/config/db", MaxResults=2)
    assert len(resp["Parameters"]) == 2
    assert resp["NextToken"] is not None


def test_get_parameter_history_next_token(ssm_with_history_params):
    first_page = ssm_with_history_params.get_parameter_history(Name="/app/config/db", MaxResults=2)
    second_page = ssm_with_history_params.get_parameter_history(Name="/app/config/db", MaxResults=2,
                                                                NextToken=first_page["NextToken"])
    assert len(second_page["Parameters"]) == 1
    assert second_page["NextToken"] is None


def test_get_parameter_history_securestring_decryption(ssm_with_history_params):
    resp = ssm_with_history_params.get_parameter_history(Name="/app/secure/secret", WithDecryption=True)
    values = [p["Value"] for p in resp["Parameters"]]
    assert values == ["secret2", "secret1"]


def test_get_parameter_history_securestring_no_decryption(ssm_with_history_params):
    resp = ssm_with_history_params.get_parameter_history(Name="/app/secure/secret", WithDecryption=False)
    for p in resp["Parameters"]:
        # values should be base64 encoded
        decoded = base64.b64decode(p["Value"].encode()).decode()
        assert decoded in ["secret1", "secret2"]


def test_get_parameter_history_missing_name(ssm_with_history_params):
    with pytest.raises(ValueError, match="Name is required"):
        ssm_with_history_params.get_parameter_history(Name=None)


def test_get_parameter_history_parameter_not_found(ssm_with_history_params):
    with pytest.raises(ValueError, match="Parameter '/nonexistent' not found"):
        ssm_with_history_params.get_parameter_history(Name="/nonexistent")


def test_label_parameter_version_single_label(ssm_with_params):
    resp = ssm_with_params.label_parameter_version(
        Name="/app/config/db", Labels=["Prod"]
    )
    assert resp["ParameterVersion"] == 1
    assert resp["InvalidLabels"] == []


def test_label_parameter_version_multiple_labels(ssm_with_params):
    resp = ssm_with_params.label_parameter_version(
        Name="/app/config/db", Labels=["Prod", "Test"]
    )
    assert resp["InvalidLabels"] == []


def test_label_parameter_version_latest_version(ssm_with_versioned_param):
    # No version specified -> should label latest version
    resp = ssm_with_versioned_param.label_parameter_version(
        Name="/app/config/db", Labels=["Latest"]
    )
    assert resp["ParameterVersion"] == 2  # latest version
    assert resp["InvalidLabels"] == []


def test_label_parameter_version_invalid_label_characters(ssm_with_params):
    resp = ssm_with_params.label_parameter_version(
        Name="/app/config/db", Labels=["", "Invalid Label!", "Valid_123"]
    )
    assert resp["InvalidLabels"] == ["", "Invalid Label!"]
    # Valid label should be applied
    param = ssm_with_params.get_parameter(Name="/app/config/db")
    latest_version = param["Parameter"]["Version"]
    labels = ssm_with_params._read_store()["/app/config/db"]["Versions"][str(latest_version)]["Labels"]
    assert "Valid_123" in labels


def test_label_parameter_version_missing_name(ssm_with_params):
    with pytest.raises(ValueError, match="Name is required"):
        ssm_with_params.label_parameter_version(Labels=["Prod"])


def test_label_parameter_version_missing_labels(ssm_with_params):
    with pytest.raises(ValueError, match="Labels must be a non-empty list"):
        ssm_with_params.label_parameter_version(Name="/app/config/db", Labels=[])


def test_label_parameter_version_invalid_type_labels(ssm_with_params):
    with pytest.raises(ValueError, match="Labels must be a non-empty list"):
        ssm_with_params.label_parameter_version(Name="/app/config/db", Labels="Prod")


def test_label_parameter_version_nonexistent_parameter(ssm_with_params):
    with pytest.raises(ValueError, match=r"Parameter '/missing' not found"):
        ssm_with_params.label_parameter_version(Name="/missing", Labels=["Prod"])


def test_label_parameter_version_nonexistent_version(ssm_with_params):
    with pytest.raises(ValueError, match=r"Version 99 does not exist"):
        ssm_with_params.label_parameter_version(Name="/app/config/db", ParameterVersion=99, Labels=["Prod"])


def test_label_parameter_version_duplicate_label(ssm_with_params):
    # Apply same label twice
    ssm_with_params.label_parameter_version(Name="/app/config/db", Labels=["Prod"])
    ssm_with_params.label_parameter_version(Name="/app/config/db", Labels=["Prod"])
    # No invalid labels, label is not duplicated in the store
    latest_version = ssm_with_params.get_parameter(Name="/app/config/db")["Parameter"]["Version"]
    labels = ssm_with_params._read_store()["/app/config/db"]["Versions"][str(latest_version)]["Labels"]
    assert labels.count("Prod") == 1


def test_label_parameter_version_multiple_invalid_labels(ssm_with_params):
    labels = ["", None, "Invalid!@#"]
    resp = ssm_with_params.label_parameter_version(Name="/app/config/db", Labels=labels)
    assert set(resp["InvalidLabels"]) == {"", None, "Invalid!@#"}


def test_unlabel_single_label(ssm_with_labeled_param):
    resp = ssm_with_labeled_param.unlabel_parameter_version(
        Name="/app/config/db", ParameterVersion=1, Labels=["Prod"]
    )
    assert resp["RemovedLabels"] == ["Prod"]
    assert resp["InvalidLabels"] == []


def test_unlabel_multiple_labels(ssm_with_labeled_param):
    resp = ssm_with_labeled_param.unlabel_parameter_version(
        Name="/app/config/db", ParameterVersion=1, Labels=["Prod", "Test"]
    )
    assert set(resp["RemovedLabels"]) == {"Prod", "Test"}
    assert resp["InvalidLabels"] == []


def test_unlabel_some_invalid_labels(ssm_with_labeled_param):
    resp = ssm_with_labeled_param.unlabel_parameter_version(
        Name="/app/config/db", ParameterVersion=1, Labels=["Prod", "NonExistent"]
    )
    assert resp["RemovedLabels"] == ["Prod"]
    assert resp["InvalidLabels"] == ["NonExistent"]


def test_unlabel_latest_version(ssm_with_versioned_labels):
    # Remove label from latest version (version 2)
    resp = ssm_with_versioned_labels.unlabel_parameter_version(
        Name="/app/config/db", ParameterVersion=2, Labels=["Latest"]
    )
    assert resp["RemovedLabels"] == ["Latest"]
    assert resp["InvalidLabels"] == []


def test_unlabel_missing_name(ssm_with_labeled_param):
    with pytest.raises(ValueError, match="Name is required"):
        ssm_with_labeled_param.unlabel_parameter_version(ParameterVersion=1, Labels=["Prod"])


def test_unlabel_missing_parameter_version(ssm_with_labeled_param):
    with pytest.raises(ValueError, match="ParameterVersion is required"):
        ssm_with_labeled_param.unlabel_parameter_version(Name="/app/config/db", Labels=["Prod"])


def test_unlabel_missing_labels(ssm_with_labeled_param):
    with pytest.raises(ValueError, match="Labels must be a non-empty list"):
        ssm_with_labeled_param.unlabel_parameter_version(Name="/app/config/db", ParameterVersion=1, Labels=[])


def test_unlabel_invalid_type_labels(ssm_with_labeled_param):
    with pytest.raises(ValueError, match="Labels must be a non-empty list"):
        ssm_with_labeled_param.unlabel_parameter_version(Name="/app/config/db", ParameterVersion=1, Labels="Prod")


def test_unlabel_nonexistent_parameter(ssm_with_labeled_param):
    with pytest.raises(ValueError, match=r"Parameter '/missing' not found"):
        ssm_with_labeled_param.unlabel_parameter_version(Name="/missing", ParameterVersion=1, Labels=["Prod"])


def test_unlabel_nonexistent_version(ssm_with_labeled_param):
    with pytest.raises(ValueError, match=r"Version 99 does not exist"):
        ssm_with_labeled_param.unlabel_parameter_version(Name="/app/config/db", ParameterVersion=99, Labels=["Prod"])


def test_unlabel_label_not_assigned(ssm_with_labeled_param):
    resp = ssm_with_labeled_param.unlabel_parameter_version(
        Name="/app/config/db", ParameterVersion=1, Labels=["NonExistent"]
    )
    assert resp["RemovedLabels"] == []
    assert resp["InvalidLabels"] == ["NonExistent"]


def test_unlabel_duplicate_labels(ssm_with_labeled_param):
    # Provide duplicate labels in request
    resp = ssm_with_labeled_param.unlabel_parameter_version(
        Name="/app/config/db", ParameterVersion=1, Labels=["Prod", "Prod"]
    )
    assert resp["RemovedLabels"] == ["Prod"]
    assert resp["InvalidLabels"] == []
