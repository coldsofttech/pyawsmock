from unittest.mock import patch, MagicMock

import pytest

from pyawsmock import configure_mock, cleanup_mock, client


@pytest.fixture
def mock_config():
    with patch("pyawsmock.config.config") as mock_cfg:
        mock_cfg.active = False
        mock_cfg.base_path = "/tmp/mock"
        yield mock_cfg


def test_configure_mock_initializes_config(mock_config):
    configure_mock(mode="persistent", path="/mockpath")
    mock_config.init.assert_called_once_with(mode="persistent", path="/mockpath")


def test_cleanup_mock_calls_cleanup(mock_config):
    cleanup_mock()
    mock_config.cleanup.assert_called_once()


@patch("pyawsmock.mocks.networking_and_content_delivery.cloudfront.mock.MockCloudFront")
def test_client_returns_mock_cloudfront(MockCloudFront, mock_config):
    mock_config.active = True
    mock_config.base_path = "/tmp/mock"

    mock_instance = MagicMock()
    MockCloudFront.return_value = mock_instance

    result = client("cloudfront", region_name="local-test")
    MockCloudFront.assert_called_once_with("/tmp/mock")
    assert result == mock_instance


def test_client_cloudfront_not_configured(mock_config):
    mock_config.active = False  # simulate mock not configured

    with pytest.raises(RuntimeError, match="Mock not configured"):
        client("cloudfront", region_name="local-test")


@pytest.mark.parametrize(
    "service_name, mock_class_path",
    [
        ("ssm", "pyawsmock.mocks.management_and_governance.ssm.mock.MockSSM"),
        ("s3", "pyawsmock.mocks.storage.s3.mock.MockS3"),
        ("codeartifact", "pyawsmock.mocks.developer_tools.codeartifact.mock.MockCodeArtifact"),
        ("sqs", "pyawsmock.mocks.application_integration.sqs.mock.MockSQS"),
    ],
)
def test_client_returns_other_mock_services(service_name, mock_class_path, mock_config):
    mock_config.active = True
    mock_config.base_path = "/tmp/mock"

    with patch("pyawsmock.mocks.base_mock.validate_region", return_value=True), \
            patch(mock_class_path) as MockService:
        mock_instance = MagicMock()
        MockService.return_value = mock_instance

        result = client(service_name, region_name="local-test")

        MockService.assert_called()
        assert result == mock_instance


def test_client_other_service_not_implemented(mock_config):
    mock_config.active = True

    with patch("pyawsmock.mocks.base_mock.validate_region", return_value=True):
        with pytest.raises(NotImplementedError, match="Local Mock not implemented for fake_service"):
            client("fake_service", region_name="local-test")


def test_client_invalid_local_region(mock_config):
    with patch("pyawsmock.mocks.base_mock.validate_region", return_value=False):
        with pytest.raises(RuntimeError, match="Region local-test not supported"):
            client("s3", region_name="local-test")


def test_client_other_service_not_configured(mock_config):
    mock_config.active = False  # not configured

    with patch("pyawsmock.mocks.base_mock.validate_region", return_value=True):
        with pytest.raises(RuntimeError, match="Mock not configured"):
            client("s3", region_name="local-test")


@patch("boto3.client")
def test_client_returns_boto3_client(mock_boto_client):
    mock_client_instance = MagicMock()
    mock_boto_client.return_value = mock_client_instance

    result = client("s3", region_name="us-east-1")

    mock_boto_client.assert_called_once_with("s3", region_name="us-east-1")
    assert result == mock_client_instance
