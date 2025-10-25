import warnings
from datetime import datetime

import pytest

from pyawsmock.mocks.networking_and_content_delivery.cloudfront.mock import MockCloudFront


@pytest.fixture
def mock_cloudfront(tmp_path):
    return MockCloudFront(base_path=tmp_path)


def test_create_oai_success(mock_cloudfront):
    config = {"CallerReference": "test123", "Comment": "My OAI"}
    result = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )

    oai = result["CloudFrontOriginAccessIdentity"]
    assert "Id" in oai
    assert "S3CanonicalUserId" in oai
    assert oai["CloudFrontOriginAccessIdentityConfig"] == config
    assert result["ETag"] == oai["ETag"]
    assert f"/2020-05-31/origin-access-identity/cloudfront/{oai['Id']}" in result["Location"]


def test_create_oai_duplicate_same_config(mock_cloudfront):
    config = {"CallerReference": "dup123", "Comment": "My OAI"}
    first = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    second = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    assert first["CloudFrontOriginAccessIdentity"]["Id"] == second["CloudFrontOriginAccessIdentity"]["Id"]
    assert first["ETag"] == second["ETag"]


def test_create_oai_duplicate_different_config_raises(mock_cloudfront):
    mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={"CallerReference": "dup456", "Comment": "First OAI"}
    )
    with pytest.raises(ValueError, match="CloudFrontOriginAccessIdentity already exists"):
        mock_cloudfront.create_cloud_front_origin_access_identity(
            CloudFrontOriginAccessIdentityConfig={"CallerReference": "dup456", "Comment": "Different comment"}
        )


@pytest.mark.parametrize(
    "config, error_msg",
    [
        (None, "CloudFrontOriginAccessIdentityConfig is required"),
        ({"Comment": "No CallerReference"}, "CallerReference is required"),
        ({"CallerReference": "abc123"}, "Comment is required"),
        ({"CallerReference": "abc123", "Comment": "a" * 129}, "Comment max 128 characters"),
    ]
)
def test_create_oai_validation_errors(mock_cloudfront, config, error_msg):
    with pytest.raises(ValueError, match=error_msg):
        mock_cloudfront.create_cloud_front_origin_access_identity(
            CloudFrontOriginAccessIdentityConfig=config
        )


def test_get_oai_success(mock_cloudfront):
    # First, create an OAI
    config = {"CallerReference": "test123", "Comment": "My OAI"}
    create_result = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    oai_id = create_result["CloudFrontOriginAccessIdentity"]["Id"]

    # Fetch the config
    result = mock_cloudfront.get_cloud_front_origin_access_identity(Id=oai_id)

    assert "CloudFrontOriginAccessIdentity" in result
    assert result["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["CallerReference"] == \
           config["CallerReference"]
    assert result["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["Comment"] == config[
        "Comment"]
    assert result["ETag"] == create_result["ETag"]


def test_get_oai_missing_id_raises(mock_cloudfront):
    with pytest.raises(ValueError, match="Id is required"):
        mock_cloudfront.get_cloud_front_origin_access_identity(Id=None)


def test_get_oai_nonexistent_id_raises(mock_cloudfront):
    fake_id = "EFAKE12345678"
    with pytest.raises(ValueError, match=f"Id '{fake_id}' does not exist"):
        mock_cloudfront.get_cloud_front_origin_access_identity(Id=fake_id)


def test_get_oai_multiple_oais(mock_cloudfront):
    # Create two OAIs
    config1 = {"CallerReference": "ref1", "Comment": "OAI 1"}
    config2 = {"CallerReference": "ref2", "Comment": "OAI 2"}
    result1 = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config1
    )
    result2 = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config2
    )

    # Fetch each config
    res1 = mock_cloudfront.get_cloud_front_origin_access_identity(Id=result1["CloudFrontOriginAccessIdentity"]["Id"])
    res2 = mock_cloudfront.get_cloud_front_origin_access_identity(Id=result2["CloudFrontOriginAccessIdentity"]["Id"])

    assert res1["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["CallerReference"] == "ref1"
    assert res2["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["CallerReference"] == "ref2"
    assert res1["ETag"] != res2["ETag"]  # Each OAI should have unique ETag


def test_get_oai_config_integrity(mock_cloudfront):
    # Create OAI and check that returned config is immutable
    config = {"CallerReference": "immutable", "Comment": "Original"}
    create_result = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    oai_id = create_result["CloudFrontOriginAccessIdentity"]["Id"]

    fetched = mock_cloudfront.get_cloud_front_origin_access_identity(Id=oai_id)
    fetched_config = fetched["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]

    # Modify the fetched dict
    fetched_config["Comment"] = "Modified"

    # Re-fetch, should not be affected
    refetched = mock_cloudfront.get_cloud_front_origin_access_identity(Id=oai_id)
    assert refetched["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["Comment"] == "Original"


def test_get_oai_config_success(mock_cloudfront):
    # First, create an OAI
    config = {"CallerReference": "test123", "Comment": "My OAI"}
    create_result = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    oai_id = create_result["CloudFrontOriginAccessIdentity"]["Id"]

    # Fetch the config
    result = mock_cloudfront.get_cloud_front_origin_access_identity_config(Id=oai_id)

    assert "CloudFrontOriginAccessIdentityConfig" in result
    assert result["CloudFrontOriginAccessIdentityConfig"]["CallerReference"] == config["CallerReference"]
    assert result["CloudFrontOriginAccessIdentityConfig"]["Comment"] == config["Comment"]
    assert result["ETag"] == create_result["ETag"]


def test_get_oai_config_missing_id_raises(mock_cloudfront):
    with pytest.raises(ValueError, match="Id is required"):
        mock_cloudfront.get_cloud_front_origin_access_identity_config(Id=None)


def test_get_oai_config_nonexistent_id_raises(mock_cloudfront):
    fake_id = "EFAKE12345678"
    with pytest.raises(ValueError, match=f"Id '{fake_id}' does not exist"):
        mock_cloudfront.get_cloud_front_origin_access_identity_config(Id=fake_id)


def test_get_oai_config_multiple_oais(mock_cloudfront):
    # Create two OAIs
    config1 = {"CallerReference": "ref1", "Comment": "OAI 1"}
    config2 = {"CallerReference": "ref2", "Comment": "OAI 2"}
    result1 = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config1
    )
    result2 = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config2
    )

    # Fetch each config
    res1 = mock_cloudfront.get_cloud_front_origin_access_identity_config(
        Id=result1["CloudFrontOriginAccessIdentity"]["Id"])
    res2 = mock_cloudfront.get_cloud_front_origin_access_identity_config(
        Id=result2["CloudFrontOriginAccessIdentity"]["Id"])

    assert res1["CloudFrontOriginAccessIdentityConfig"]["CallerReference"] == "ref1"
    assert res2["CloudFrontOriginAccessIdentityConfig"]["CallerReference"] == "ref2"
    assert res1["ETag"] != res2["ETag"]  # Each OAI should have unique ETag


def test_get_oai_config_config_integrity(mock_cloudfront):
    # Create OAI and check that returned config is immutable
    config = {"CallerReference": "immutable", "Comment": "Original"}
    create_result = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    oai_id = create_result["CloudFrontOriginAccessIdentity"]["Id"]

    fetched = mock_cloudfront.get_cloud_front_origin_access_identity_config(Id=oai_id)
    fetched_config = fetched["CloudFrontOriginAccessIdentityConfig"]

    # Modify the fetched dict
    fetched_config["Comment"] = "Modified"

    # Re-fetch, should not be affected
    refetched = mock_cloudfront.get_cloud_front_origin_access_identity_config(Id=oai_id)
    assert refetched["CloudFrontOriginAccessIdentityConfig"]["Comment"] == "Original"


def test_delete_oai_success(mock_cloudfront):
    # Create an OAI first
    config = {"CallerReference": "delete-test", "Comment": "To be deleted"}
    create_result = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    oai_id = create_result["CloudFrontOriginAccessIdentity"]["Id"]
    etag = create_result["ETag"]

    # Delete it
    result = mock_cloudfront.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag)
    assert result is None

    # Verify deletion
    with pytest.raises(ValueError, match=f"Id '{oai_id}' does not exist"):
        mock_cloudfront.get_cloud_front_origin_access_identity(Id=oai_id)


def test_delete_oai_missing_id_raises(mock_cloudfront):
    with pytest.raises(ValueError, match="Id is required"):
        mock_cloudfront.delete_cloud_front_origin_access_identity(Id=None)


def test_delete_oai_nonexistent_id_raises(mock_cloudfront):
    fake_id = "EFAKE12345678"
    with pytest.raises(ValueError, match=f"Id '{fake_id}' does not exist"):
        mock_cloudfront.delete_cloud_front_origin_access_identity(Id=fake_id)


def test_delete_oai_etag_mismatch_raises(mock_cloudfront):
    config = {"CallerReference": "etag-test", "Comment": "ETag mismatch"}
    create_result = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    oai_id = create_result["CloudFrontOriginAccessIdentity"]["Id"]

    fake_etag = "wrong-etag"
    with pytest.raises(ValueError, match="ETag does not match"):
        mock_cloudfront.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=fake_etag)


def test_delete_oai_without_ifmatch(mock_cloudfront):
    # Create an OAI
    config = {"CallerReference": "no-ifmatch", "Comment": "No IfMatch"}
    create_result = mock_cloudfront.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig=config
    )
    oai_id = create_result["CloudFrontOriginAccessIdentity"]["Id"]

    # Deleting without IfMatch should succeed
    result = mock_cloudfront.delete_cloud_front_origin_access_identity(Id=oai_id)
    assert result is None

    with pytest.raises(ValueError, match=f"Id '{oai_id}' does not exist"):
        mock_cloudfront.get_cloud_front_origin_access_identity(Id=oai_id)


def test_delete_multiple_oais(mock_cloudfront):
    # Create multiple OAIs
    configs = [
        {"CallerReference": "multi1", "Comment": "OAI1"},
        {"CallerReference": "multi2", "Comment": "OAI2"},
    ]
    created_ids = []
    for cfg in configs:
        res = mock_cloudfront.create_cloud_front_origin_access_identity(
            CloudFrontOriginAccessIdentityConfig=cfg
        )
        created_ids.append(res["CloudFrontOriginAccessIdentity"]["Id"])

    # Delete the first OAI
    mock_cloudfront.delete_cloud_front_origin_access_identity(Id=created_ids[0])

    # First OAI should not exist
    with pytest.raises(ValueError, match=f"Id '{created_ids[0]}' does not exist"):
        mock_cloudfront.get_cloud_front_origin_access_identity(Id=created_ids[0])

    # Second OAI should still exist
    oai2 = mock_cloudfront.get_cloud_front_origin_access_identity(Id=created_ids[1])
    assert oai2["CloudFrontOriginAccessIdentity"]["Id"] == created_ids[1]


def test_create_distribution_success(mock_cloudfront):
    dist_config = {
        "CallerReference": "test-dist-1",
        "Enabled": True,
        "Origins": [{"Id": "origin1", "DomainName": "example.com"}],
        "DefaultCacheBehavior": {"TargetOriginId": "origin1", "ViewerProtocolPolicy": "allow-all"},
        "Comment": "Test Comment"
    }

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = mock_cloudfront.create_distribution(DistributionConfig=dist_config)

    dist = result["Distribution"]
    assert dist["DistributionConfig"] == dist_config
    assert dist["Status"] == "Deployed"
    assert result["Location"].endswith(dist["Id"])
    assert "ETag" in result
    # Warning should have been issued for mock limitation
    assert any("local mock does not perform complete validation" in str(warn.message) for warn in w)


def test_create_distribution_missing_config_raises(mock_cloudfront):
    with pytest.raises(ValueError, match="DistributionConfig is required"):
        mock_cloudfront.create_distribution()


def test_create_distribution_duplicate_caller_reference_returns_existing(mock_cloudfront):
    dist_config = {
        "CallerReference": "duplicate-caller",
        "Enabled": True,
        "Origins": [{"Id": "origin1", "DomainName": "example.com"}],
        "DefaultCacheBehavior": {"TargetOriginId": "origin1", "ViewerProtocolPolicy": "allow-all"},
        "Comment": "Test Comment"
    }

    # Create first distribution
    first_result = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id_first = first_result["Distribution"]["Id"]

    # Create another with same CallerReference
    second_result = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id_second = second_result["Distribution"]["Id"]

    # It should return the same distribution
    assert dist_id_first == dist_id_second
    assert second_result["Distribution"]["DistributionConfig"] == dist_config


def test_create_multiple_distributions(mock_cloudfront):
    configs = [
        {"CallerReference": f"dist{i}", "Enabled": True,
         "Origins": [{"Id": f"origin{i}", "DomainName": "example.com"}],
         "DefaultCacheBehavior": {"TargetOriginId": f"origin{i}", "ViewerProtocolPolicy": "allow-all"},
         "Comment": f"testComment{i}"}
        for i in range(3)
    ]

    ids = set()
    for cfg in configs:
        result = mock_cloudfront.create_distribution(DistributionConfig=cfg)
        ids.add(result["Distribution"]["Id"])

    # All distributions should have unique IDs
    assert len(ids) == len(configs)


def test_create_distribution_fields(mock_cloudfront):
    dist_config = {
        "CallerReference": "field-test",
        "Enabled": True,
        "Origins": [{"Id": "origin1", "DomainName": "example.com"}],
        "DefaultCacheBehavior": {"TargetOriginId": "origin1", "ViewerProtocolPolicy": "allow-all"},
        "Comment": "Test Comment"
    }
    result = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist = result["Distribution"]

    # Basic fields
    assert dist["Id"].startswith("ED")
    assert dist["DomainName"].endswith(".cloudfront.pyawsmock.local")
    assert dist["ARN"].startswith("arn:mock:cloudfront")
    # LastModifiedTime is a valid ISO string
    datetime.fromisoformat(dist["LastModifiedTime"])


def test_get_distribution_success(mock_cloudfront):
    # First, create a distribution
    dist_config = {
        "CallerReference": "test-get-dist",
        "Enabled": True,
        "Origins": [{"Id": "origin1", "DomainName": "example.com"}],
        "DefaultCacheBehavior": {"TargetOriginId": "origin1", "ViewerProtocolPolicy": "allow-all"},
        "Comment": "Test Comment"
    }

    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]

    # Now get the distribution
    result_get = mock_cloudfront.get_distribution(Id=dist_id)
    dist = result_get["Distribution"]

    # Basic validations
    assert dist["Id"] == dist_id
    assert dist["Status"] == "Deployed"
    assert isinstance(dist["LastModifiedTime"], datetime)
    assert dist["DistributionConfig"] == dist_config
    assert "ETag" in result_get


def test_get_distribution_missing_id(mock_cloudfront):
    with pytest.raises(ValueError, match="Id is required"):
        mock_cloudfront.get_distribution()


def test_get_distribution_non_existent_id(mock_cloudfront):
    with pytest.raises(ValueError, match="Id 'NONEXISTENTID' does not exist"):
        mock_cloudfront.get_distribution(Id="NONEXISTENTID")


def test_get_distribution_default_optional_fields(mock_cloudfront):
    # Create a distribution without optional fields
    dist_config = {
        "CallerReference": "test-default-fields",
        "Enabled": True,
        "Origins": [{"Id": "origin1", "DomainName": "example.com"}],
        "DefaultCacheBehavior": {"TargetOriginId": "origin1", "ViewerProtocolPolicy": "allow-all"},
        "Comment": "Test Comment"
    }

    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]

    # Manually remove optional fields from store to simulate minimal mock
    store = mock_cloudfront._read_dist_store()
    dist_data = store[dist_id]
    dist_data.pop("ActiveTrustedSigners", None)
    dist_data.pop("ActiveTrustedKeyGroups", None)
    dist_data.pop("AliasICPRecordals", None)
    mock_cloudfront._write_dist_store(store)

    # Retrieve the distribution
    result_get = mock_cloudfront.get_distribution(Id=dist_id)
    dist = result_get["Distribution"]

    # Default fallback values
    assert dist["ActiveTrustedSigners"] == {"Enabled": False, "Quantity": 0, "Items": []}
    assert dist["ActiveTrustedKeyGroups"] == {"Enabled": False, "Quantity": 0, "Items": []}
    assert dist["AliasICPRecordals"] == []


def test_get_distribution_config_success(mock_cloudfront):
    # Create a distribution first
    dist_config = {
        "CallerReference": "test-get-dist-config",
        "Enabled": True,
        "Origins": [{"Id": "origin1", "DomainName": "example.com"}],
        "DefaultCacheBehavior": {"TargetOriginId": "origin1", "ViewerProtocolPolicy": "allow-all"},
        "Comment": "Test Comment"
    }

    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]

    # Retrieve the distribution config
    result_get = mock_cloudfront.get_distribution_config(Id=dist_id)
    assert result_get["DistributionConfig"] == dist_config
    assert "ETag" in result_get


def test_get_distribution_config_missing_id(mock_cloudfront):
    # Calling without ID should raise an error
    with pytest.raises(ValueError, match="Id is required"):
        mock_cloudfront.get_distribution_config()


def test_get_distribution_config_non_existent_id(mock_cloudfront):
    # Calling with a non-existent ID should raise an error
    with pytest.raises(ValueError, match="Id 'NONEXISTENTID' does not exist"):
        mock_cloudfront.get_distribution_config(Id="NONEXISTENTID")


def test_get_distribution_config_mock_limitations(mock_cloudfront):
    # Create a distribution
    dist_config = {
        "CallerReference": "test-mock-limitation",
        "Enabled": True,
        "Origins": [{"Id": "origin1", "DomainName": "example.com"}],
        "DefaultCacheBehavior": {"TargetOriginId": "origin1", "ViewerProtocolPolicy": "allow-all"},
        "Comment": "Test Comment"
    }

    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]

    # Remove DistributionConfig manually to simulate mock limitation
    store = mock_cloudfront._read_dist_store()
    store[dist_id].pop("DistributionConfig", None)
    mock_cloudfront._write_dist_store(store)

    # In this mock, get_distribution_config should raise KeyError if DistributionConfig is missing
    with pytest.raises(KeyError):
        mock_cloudfront.get_distribution_config(Id=dist_id)


def test_update_distribution_success(mock_cloudfront):
    # Create initial distribution
    dist_config = {
        "CallerReference": "update-success",
        "Enabled": True,
        "Origins": [{"Id": "origin1", "DomainName": "example.com"}],
        "DefaultCacheBehavior": {"TargetOriginId": "origin1", "ViewerProtocolPolicy": "allow-all"},
        "Comment": "Test Comment"
    }

    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]
    etag_before = result_create["ETag"]

    # Update distribution
    updated_config = dist_config.copy()
    updated_config["Enabled"] = False

    result_update = mock_cloudfront.update_distribution(
        Id=dist_id,
        IfMatch=etag_before,
        DistributionConfig=updated_config
    )

    assert result_update["Distribution"]["Id"] == dist_id
    assert result_update["Distribution"]["DistributionConfig"]["Enabled"] is False
    assert result_update["ETag"] != etag_before  # ETag should change
    assert "LastModifiedTime" in result_update["Distribution"]


def test_update_distribution_missing_id(mock_cloudfront):
    with pytest.raises(ValueError, match="DistributionConfig is required"):
        mock_cloudfront.update_distribution(IfMatch="etag", DistributionConfig={})


def test_update_distribution_missing_if_match(mock_cloudfront):
    # Create distribution
    dist_config = {"CallerReference": "missing-ifmatch", "Enabled": True, "Comment": "Test Comment"}
    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]

    with pytest.raises(ValueError, match="IfMatch is required"):
        mock_cloudfront.update_distribution(Id=dist_id, DistributionConfig=dist_config)


def test_update_distribution_missing_config(mock_cloudfront):
    # Create distribution
    dist_config = {"CallerReference": "missing-config", "Enabled": True, "Comment": "Test Comment"}
    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]
    etag = result_create["ETag"]

    with pytest.raises(ValueError, match="DistributionConfig is required"):
        mock_cloudfront.update_distribution(Id=dist_id, IfMatch=etag)


def test_update_distribution_non_existent_id(mock_cloudfront):
    with pytest.raises(ValueError, match="DistributionConfig is required"):
        mock_cloudfront.update_distribution(Id="NONEXISTENTID", IfMatch="etag", DistributionConfig={})


def test_update_distribution_etag_mismatch(mock_cloudfront):
    # Create distribution
    dist_config = {"CallerReference": "etag-mismatch", "Enabled": True, "Comment": "Test Comment"}
    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]

    # Provide incorrect IfMatch
    with pytest.raises(ValueError, match="ETag does not match"):
        mock_cloudfront.update_distribution(Id=dist_id, IfMatch="WRONGETAG", DistributionConfig=dist_config)


def test_update_distribution_mock_limitations_warns(mock_cloudfront, monkeypatch):
    import warnings

    # Create distribution
    dist_config = {"CallerReference": "mock-limitation", "Enabled": True, "Comment": "Test Comment"}
    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]
    etag = result_create["ETag"]

    updated_config = dist_config.copy()
    updated_config["Enabled"] = False

    # Check that warning is issued
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        mock_cloudfront.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=updated_config)
        assert any("local mock does not perform complete validation" in str(wi.message) for wi in w)


def test_delete_distribution_success(mock_cloudfront):
    # Create distribution
    dist_config = {"CallerReference": "delete-success", "Enabled": False, "Comment": "Test Comment"}
    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]
    etag = result_create["ETag"]

    # Delete distribution
    result_delete = mock_cloudfront.delete_distribution(Id=dist_id, IfMatch=etag)
    assert result_delete is None

    # Ensure distribution is removed
    with pytest.raises(ValueError, match=f"Id '{dist_id}' does not exist"):
        mock_cloudfront.get_distribution(Id=dist_id)


def test_delete_distribution_enabled_distribution(mock_cloudfront):
    # Create distribution enabled
    dist_config = {"CallerReference": "delete-enabled", "Enabled": True, "Comment": "Test Comment"}
    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]
    etag = result_create["ETag"]

    # Attempt to delete should fail
    with pytest.raises(ValueError, match="Cannot delete a distribution that is enabled"):
        mock_cloudfront.delete_distribution(Id=dist_id, IfMatch=etag)


def test_delete_distribution_missing_id(mock_cloudfront):
    with pytest.raises(ValueError, match="Id is required"):
        mock_cloudfront.delete_distribution(IfMatch="etag")


def test_delete_distribution_missing_if_match(mock_cloudfront):
    # Create a distribution
    dist_config = {"CallerReference": "missing-ifmatch", "Enabled": False, "Comment": "Test Comment"}
    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]

    with pytest.raises(ValueError, match="IfMatch is required"):
        mock_cloudfront.delete_distribution(Id=dist_id)


def test_delete_distribution_non_existent_id(mock_cloudfront):
    with pytest.raises(ValueError, match="Id 'NONEXISTENTID' does not exist"):
        mock_cloudfront.delete_distribution(Id="NONEXISTENTID", IfMatch="etag")


def test_delete_distribution_etag_mismatch(mock_cloudfront):
    # Create distribution
    dist_config = {"CallerReference": "etag-mismatch", "Enabled": False, "Comment": "Test Comment"}
    result_create = mock_cloudfront.create_distribution(DistributionConfig=dist_config)
    dist_id = result_create["Distribution"]["Id"]

    # Provide incorrect IfMatch
    with pytest.raises(ValueError, match="ETag does not match"):
        mock_cloudfront.delete_distribution(Id=dist_id, IfMatch="WRONGETAG")
