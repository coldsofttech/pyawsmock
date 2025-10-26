import os
import time
import uuid
from datetime import datetime, timezone
from hashlib import md5
from unittest.mock import patch

import pytest

from pyawsmock.mocks.application_integration.sqs.mock import MockSQS

pytestmark = pytest.mark.order(6)


@pytest.fixture
def sqs_with_empty_store(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")
    mock._write_store({})
    return mock


@pytest.fixture
def sqs_with_queues(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")
    queues = {
        "orders": {
            "Name": "orders",
            "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/orders",
            "Attributes": {"FifoQueue": "false"},
        },
        "payments.fifo": {
            "Name": "payments.fifo",
            "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/payments.fifo",
            "Attributes": {"FifoQueue": "true"},
        },
    }
    mock._write_store(queues)
    return mock


@pytest.fixture
def sqs_with_attributes(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")
    queue_name = "test-queue"
    queue_url = f"http://sqs.local-us-east-1.pyawsmock.local/000000000000/{queue_name}"
    queue_data = {
        queue_name: {
            "Name": queue_name,
            "Url": queue_url,
            "Owner": "000000000000",
            "Attributes": {
                "DelaySeconds": "0",
                "MaximumMessageSize": "262144",
                "MessageRetentionPeriod": "345600",
                "ReceiveMessageWaitTimeSeconds": "0",
                "VisibilityTimeout": "30",
                "FifoQueue": "false",
                "ContentBasedDeduplication": "false",
                "QueueArn": f"arn:mock:sqs:local-us-east-1:000000000000:{queue_name}",
            },
        }
    }
    mock._write_store(queue_data)
    return mock


@pytest.fixture
def sqs_with_multiple_queues(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")

    queues = {
        "queue1": {
            "Name": "queue1",
            "Owner": "000000000000",
            "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queue1",
            "Attributes": {"FifoQueue": "false"},
        },
        "queue2": {
            "Name": "queue2",
            "Owner": "000000000000",
            "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queue2",
            "Attributes": {"FifoQueue": "false"},
        },
        "orders.fifo": {
            "Name": "orders.fifo",
            "Owner": "000000000000",
            "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/orders.fifo",
            "Attributes": {"FifoQueue": "true"},
        },
        "logs.fifo": {
            "Name": "logs.fifo",
            "Owner": "000000000000",
            "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/logs.fifo",
            "Attributes": {"FifoQueue": "true"},
        },
    }

    mock._write_store(queues)
    return mock


@pytest.fixture
def sqs_with_messages(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")

    queue_name = "my-queue"
    queue_id = "q-123"
    queue_url = f"http://sqs.local-us-east-1.pyawsmock.local/000000000000/{queue_name}"

    store_data = {
        queue_name: {
            "Id": queue_id,
            "Name": queue_name,
            "Owner": "000000000000",
            "Url": queue_url,
            "Attributes": {"FifoQueue": "false"},
        }
    }
    mock._write_store(store_data)

    mock.data_path = tmp_path / "local-us-east-1" / "SQS"
    mock._write_data_store(queue_name, queue_id, {
        "Messages": [{"id": "1", "body": "msg1"}],
        "InFlightMessages": [{"id": "2", "body": "msg2"}],
        "LastPurgeTimestamp": None,
    })

    return mock


@pytest.fixture
def sqs_with_multiple_queues_and_messages(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")

    # Queue A
    mock._write_store({
        "queueA": {"Id": "q-1", "Name": "queueA", "Owner": "000000000000",
                   "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queueA"},
        "queueB": {"Id": "q-2", "Name": "queueB", "Owner": "000000000000",
                   "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queueB"},
    })

    mock._write_data_store("queueA", "q-1",
                           {"Messages": [{"id": 1}], "InFlightMessages": [], "LastPurgeTimestamp": None})
    mock._write_data_store("queueB", "q-2",
                           {"Messages": [{"id": 2}], "InFlightMessages": [], "LastPurgeTimestamp": None})

    return mock


def make_message(body="Test", receipt_handle=None):
    now = datetime.now(timezone.utc)
    receipt_handle = receipt_handle or str(uuid.uuid4())
    return {
        "MessageId": str(uuid.uuid4()),
        "ReceiptHandle": receipt_handle,
        "MessageBody": body,
        "SentTimestamp": int(now.timestamp() * 1000),
        "ApproximateReceiveCount": 0,
        "VisibleAfter": now.timestamp(),
        "MessageAttributes": {},
        "MessageSystemAttributes": {},
    }


def test_create_queue_success(sqs_with_empty_store):
    result = sqs_with_empty_store.create_queue(QueueName="MyQueue")
    assert "QueueUrl" in result
    assert result["QueueUrl"].endswith("pyawsmock.local/000000000000/MyQueue")


def test_create_queue_missing_name(sqs_with_empty_store):
    with pytest.raises(ValueError, match="QueueName is required"):
        sqs_with_empty_store.create_queue()


@pytest.mark.parametrize("name", ["queue!", "bad@name", "white space"])
def test_create_queue_invalid_characters(sqs_with_empty_store, name):
    with pytest.raises(ValueError, match="alphanumeric characters"):
        sqs_with_empty_store.create_queue(QueueName=name)


def test_create_queue_name_too_long(sqs_with_empty_store):
    long_name = "a" * 81
    with pytest.raises(ValueError, match="max of 80 characters"):
        sqs_with_empty_store.create_queue(QueueName=long_name)


def test_create_fifo_queue_missing_suffix(sqs_with_empty_store):
    with pytest.raises(ValueError, match=".fifo"):
        sqs_with_empty_store.create_queue(QueueName="myfifoqueue", Attributes={"FifoQueue": "true"})


def test_create_fifo_queue_success(sqs_with_empty_store):
    result = sqs_with_empty_store.create_queue(QueueName="orders.fifo", Attributes={"FifoQueue": "true"})
    assert result["QueueUrl"].endswith(".fifo")
    store = sqs_with_empty_store._read_store()
    assert store["orders.fifo"]["Attributes"]["FifoQueue"] == "true"


def test_create_queue_already_exists(sqs_with_empty_store):
    store = sqs_with_empty_store._read_store()
    store["orders"] = {"Name": "orders"}
    sqs_with_empty_store._write_store(store)
    with pytest.raises(ValueError, match="already exists"):
        sqs_with_empty_store.create_queue(QueueName="orders")


def test_create_queue_sets_default_attributes(sqs_with_empty_store):
    sqs_with_empty_store.create_queue(QueueName="defaultQueue")
    queue = sqs_with_empty_store._read_store()["defaultQueue"]
    assert isinstance(queue["Attributes"], dict)


def test_queue_name_case_sensitive(sqs_with_empty_store):
    store: dict = {"Orders": {"Name": "Orders"}}
    sqs_with_empty_store._write_store(store)
    # “orders” should not conflict with “Orders”
    result = sqs_with_empty_store.create_queue(QueueName="orders")
    assert result["QueueUrl"].endswith("orders")


def test_queue_url_format(sqs_with_empty_store):
    result = sqs_with_empty_store.create_queue(QueueName="MyQueue_123")
    assert result["QueueUrl"].startswith("http://sqs.")
    assert result["QueueUrl"].endswith("MyQueue_123")


def test_create_queue_preserves_passed_attributes(sqs_with_empty_store):
    attrs = {"DelaySeconds": "10", "FifoQueue": "false"}
    sqs_with_empty_store.create_queue(QueueName="attrQueue", Attributes=attrs)
    queue = sqs_with_empty_store._read_store()["attrQueue"]
    for attr in attrs:
        assert attr in queue["Attributes"]


def test_create_queue_empty_store_initialization(sqs_with_empty_store):
    sqs_with_empty_store._write_store({})
    sqs_with_empty_store.create_queue(QueueName="TestQueue")
    assert any(q["Name"] == "TestQueue" for q in sqs_with_empty_store._read_store().values())


def test_fifo_suffix_without_fifo_attribute(sqs_with_empty_store):
    result = sqs_with_empty_store.create_queue(QueueName="myqueue.fifo")
    assert result["QueueUrl"].endswith(".fifo")


def test_get_queue_url_success(sqs_with_queues):
    response = sqs_with_queues.get_queue_url(QueueName="orders")
    assert "QueueUrl" in response
    assert response["QueueUrl"].endswith("orders")


def test_get_queue_url_missing_name(sqs_with_queues):
    with pytest.raises(ValueError) as exc:
        sqs_with_queues.get_queue_url()
    assert "QueueName is required" in str(exc.value)


def test_get_queue_url_not_found(sqs_with_empty_store):
    with pytest.raises(ValueError) as exc:
        sqs_with_empty_store.get_queue_url(QueueName="unknown-queue")
    assert "does not exist" in str(exc.value)


def test_get_queue_url_case_sensitive(sqs_with_queues):
    # Should fail if names are case-sensitive
    with pytest.raises(ValueError) as exc:
        sqs_with_queues.get_queue_url(QueueName="Test-Queue")
    assert "does not exist" in str(exc.value)


def test_get_queue_url_for_fifo_queue(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")
    fifo_name = "my-queue.fifo"
    fifo_data = {
        fifo_name: {
            "Name": fifo_name,
            "Url": f"http://localhost:4566/000000000000/{fifo_name}",
            "Attributes": {"FifoQueue": "true"},
        }
    }
    mock._write_store(fifo_data)

    response = mock.get_queue_url(QueueName=fifo_name)
    assert response["QueueUrl"].endswith(".fifo")


def test_set_single_valid_attribute(sqs_with_attributes):
    queue_url = sqs_with_attributes._read_store()["test-queue"]["Url"]
    sqs_with_attributes.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"VisibilityTimeout": "45"}
    )

    updated = sqs_with_attributes._read_store()["test-queue"]["Attributes"]
    assert updated["VisibilityTimeout"] == "45"


def test_set_multiple_attributes(sqs_with_attributes):
    queue_url = sqs_with_attributes._read_store()["test-queue"]["Url"]
    sqs_with_attributes.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "DelaySeconds": "10",
            "MaximumMessageSize": "512000"
        }
    )

    attrs = sqs_with_attributes._read_store()["test-queue"]["Attributes"]
    assert attrs["DelaySeconds"] == "10"
    assert attrs["MaximumMessageSize"] == "512000"


def test_set_attribute_requires_queue_url(sqs_with_attributes):
    with pytest.raises(ValueError) as exc:
        sqs_with_attributes.set_queue_attributes(
            Attributes={"DelaySeconds": "5"}
        )
    assert "QueueUrl is required" in str(exc.value)


def test_set_attribute_requires_attributes_dict(sqs_with_attributes):
    queue_url = sqs_with_attributes._read_store()["test-queue"]["Url"]
    with pytest.raises(ValueError) as exc:
        sqs_with_attributes.set_queue_attributes(QueueUrl=queue_url)
    assert "Attributes is required" in str(exc.value)


def test_invalid_attribute_key(sqs_with_attributes):
    queue_url = sqs_with_attributes._read_store()["test-queue"]["Url"]
    with pytest.raises(ValueError) as exc:
        sqs_with_attributes.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={"InvalidKey": "10"}
        )
    assert "Invalid Attribute" in str(exc.value)


def test_readonly_attribute_change(sqs_with_attributes):
    queue_url = sqs_with_attributes._read_store()["test-queue"]["Url"]
    with pytest.raises(ValueError) as exc:
        sqs_with_attributes.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={"QueueArn": "arn:aws:sqs:fake"}
        )
    assert "Cannot modify read-only" in str(exc.value)


def test_fifo_queue_preserves_flag(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")
    fifo_name = "myqueue.fifo"
    fifo_url = f"http://sqs.local-us-east-1.pyawsmock.local/000000000000/{fifo_name}"
    mock._write_store({
        fifo_name: {
            "Name": fifo_name,
            "Url": fifo_url,
            "Owner": "000000000000",
            "Attributes": {"FifoQueue": "true", "VisibilityTimeout": "30"},
        }
    })
    mock.set_queue_attributes(
        QueueUrl=fifo_url,
        Attributes={"VisibilityTimeout": "50"}
    )
    attrs = mock._read_store()[fifo_name]["Attributes"]
    assert attrs["VisibilityTimeout"] == "50"
    assert attrs["FifoQueue"] == "true"


def test_store_updated_persistently(sqs_with_attributes):
    queue_url = sqs_with_attributes._read_store()["test-queue"]["Url"]
    sqs_with_attributes.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"DelaySeconds": "12"}
    )

    reloaded = sqs_with_attributes._read_store()
    assert reloaded["test-queue"]["Attributes"]["DelaySeconds"] == "12"


def test_get_queue_attributes_all(sqs_with_attributes):
    mock = sqs_with_attributes
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue"

    response = mock.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["All"]
    )

    assert "Attributes" in response
    attrs = response["Attributes"]

    # Common attributes should exist
    assert attrs["FifoQueue"] == "false"
    assert attrs["QueueArn"].endswith(":test-queue")
    assert attrs["DelaySeconds"] == "0"


def test_get_queue_attributes_subset(sqs_with_attributes):
    mock = sqs_with_attributes
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue"

    response = mock.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["VisibilityTimeout", "FifoQueue"]
    )

    attrs = response["Attributes"]
    assert attrs["VisibilityTimeout"] == "30"
    assert attrs["FifoQueue"] == "false"


def test_get_queue_attributes_empty_request(sqs_with_attributes):
    mock = sqs_with_attributes
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue"

    response = mock.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=[]
    )

    assert response["Attributes"] != {}


def test_get_queue_attributes_invalid_name(sqs_with_attributes):
    mock = sqs_with_attributes
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue"

    with pytest.raises(ValueError, match="Invalid Attribute"):
        mock.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["InvalidAttribute"]
        )


def test_get_queue_attributes_missing_queue(sqs_with_attributes):
    mock = sqs_with_attributes
    with pytest.raises(ValueError, match="Queue unknown-queue does not exist"):
        mock.get_queue_attributes(
            QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/unknown-queue",
            AttributeNames=["All"]
        )


def test_get_queue_attributes_case_sensitive(sqs_with_attributes):
    mock = sqs_with_attributes
    # URL has different case → should fail if your mock is case-sensitive
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/Test-Queue"

    with pytest.raises(ValueError, match="Queue Test-Queue does not exist"):
        mock.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])


def test_get_queue_attributes_missing_url(sqs_with_attributes):
    mock = sqs_with_attributes

    with pytest.raises(ValueError, match="QueueUrl is required"):
        mock.get_queue_attributes(AttributeNames=["All"])


def test_get_queue_attributes_fifo_flag(sqs_with_attributes):
    mock = sqs_with_attributes
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue"

    attrs = mock.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["FifoQueue"])["Attributes"]
    assert attrs["FifoQueue"] == "false"

    # Now modify queue to non-FIFO
    data = mock._read_store()
    queue = data.pop("test-queue")
    queue["Name"] = "test-queue.fifo"
    queue["Url"] = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo"
    queue["Attributes"]["FifoQueue"] = "true"
    data["test-queue.fifo"] = queue
    mock._write_store(data)

    attrs = \
        mock.get_queue_attributes(QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo",
                                  AttributeNames=["FifoQueue"])["Attributes"]
    assert attrs["FifoQueue"] == "true"


def test_list_queues_all(sqs_with_multiple_queues):
    mock = sqs_with_multiple_queues
    response = mock.list_queues()

    assert "QueueUrls" in response
    urls = response["QueueUrls"]
    assert len(urls) == 4
    assert any("queue1" in u for u in urls)
    assert any("orders.fifo" in u for u in urls)


def test_list_queues_with_prefix(sqs_with_multiple_queues):
    mock = sqs_with_multiple_queues
    response = mock.list_queues(QueueNamePrefix="queue")

    urls = response["QueueUrls"]
    assert len(urls) == 2
    assert all(u.endswith("queue1") or u.endswith("queue2") for u in urls)


def test_list_queues_no_match(sqs_with_multiple_queues):
    mock = sqs_with_multiple_queues
    response = mock.list_queues(QueueNamePrefix="unknown")

    assert "QueueUrls" in response
    assert response["QueueUrls"] == []


def test_list_queues_fifo_prefix(sqs_with_multiple_queues):
    mock = sqs_with_multiple_queues
    response = mock.list_queues(QueueNamePrefix="orders")

    urls = response["QueueUrls"]
    assert len(urls) == 1
    assert urls[0].endswith("orders.fifo")


def test_list_queues_case_sensitivity(sqs_with_multiple_queues):
    mock = sqs_with_multiple_queues
    response = mock.list_queues(QueueNamePrefix="QUEUE")  # upper case

    # AWS SQS names are case-sensitive
    assert response["QueueUrls"] == []


def test_list_queues_empty_store(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")
    mock._write_store({})

    response = mock.list_queues()
    assert response["QueueUrls"] == []


def test_list_queues_corrupt_store(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")
    # Write something unexpected
    mock._write_store({"invalid": None})

    with pytest.raises(TypeError):
        mock.list_queues()


def test_list_queues_response_structure(sqs_with_multiple_queues):
    mock = sqs_with_multiple_queues
    response = mock.list_queues()

    # Should always have consistent structure
    assert isinstance(response, dict)
    assert "QueueUrls" in response
    assert isinstance(response["QueueUrls"], list)


def test_list_queues_partial_prefix_match(sqs_with_multiple_queues):
    mock = sqs_with_multiple_queues
    response = mock.list_queues(QueueNamePrefix="log")

    urls = response["QueueUrls"]
    assert len(urls) == 1
    assert urls[0].endswith("logs.fifo")


def test_list_queues_empty_prefix(sqs_with_multiple_queues):
    mock = sqs_with_multiple_queues
    response = mock.list_queues(QueueNamePrefix="")

    urls = response["QueueUrls"]
    assert len(urls) == 4


def test_purge_queue_clears_messages_and_updates_timestamp(sqs_with_messages):
    mock = sqs_with_messages
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/my-queue"

    # Before purge
    queue_info, _ = mock._get_queue_info(queue_url, url_mode=True)
    before_data = mock._read_data_store(queue_info["Name"], queue_info["Id"])
    assert before_data["Messages"]
    assert before_data["InFlightMessages"]

    # Perform purge
    mock.purge_queue(QueueUrl=queue_url)

    # After purge
    after_data = mock._read_data_store(queue_info["Name"], queue_info["Id"])
    assert after_data["Messages"] == []
    assert after_data["InFlightMessages"] == []
    assert after_data["LastPurgeTimestamp"] is not None

    ts = datetime.fromisoformat(after_data["LastPurgeTimestamp"])
    assert ts.tzinfo == timezone.utc


def test_purge_empty_queue_updates_timestamp(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")

    queue_name = "empty-queue"
    queue_id = "q-999"
    queue_url = f"http://sqs.local-us-east-1.pyawsmock.local/000000000000/{queue_name}"

    mock._write_store({
        queue_name: {"Id": queue_id, "Name": queue_name, "Owner": "000000000000", "Url": queue_url}
    })
    mock._write_data_store(queue_name, queue_id, {
        "Messages": [],
        "InFlightMessages": [],
        "LastPurgeTimestamp": None,
    })

    mock.purge_queue(QueueUrl=queue_url)
    data = mock._read_data_store(queue_name, queue_id)

    assert data["Messages"] == []
    assert data["InFlightMessages"] == []
    assert data["LastPurgeTimestamp"] is not None


def test_purge_nonexistent_queue_raises_error(sqs_with_messages):
    mock = sqs_with_messages
    with pytest.raises(Exception) as exc:
        mock.purge_queue(QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/missing-queue")
    assert "Queue missing-queue does not exist" in str(exc.value)


def test_purge_invalid_queue_url_format(sqs_with_messages):
    mock = sqs_with_messages
    with pytest.raises(Exception) as exc:
        mock.purge_queue(QueueUrl="not-a-valid-url")
    assert "Invalid QueueUrl" in str(exc.value)


def test_purge_does_not_affect_other_queues(tmp_path):
    mock = MockSQS(base_path=tmp_path, region_name="local-us-east-1")

    # Create queue A and B
    store = {
        "queueA": {"Id": "q-1", "Name": "queueA", "Owner": "000000000000",
                   "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queueA"},
        "queueB": {"Id": "q-2", "Name": "queueB", "Owner": "000000000000",
                   "Url": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queueB"},
    }
    mock._write_store(store)

    mock._write_data_store("queueA", "q-1",
                           {"Messages": [{"id": 1}], "InFlightMessages": [], "LastPurgeTimestamp": None})
    mock._write_data_store("queueB", "q-2",
                           {"Messages": [{"id": 2}], "InFlightMessages": [], "LastPurgeTimestamp": None})

    # Purge queueA
    mock.purge_queue(QueueUrl=store["queueA"]["Url"])

    a_data = mock._read_data_store("queueA", "q-1")
    b_data = mock._read_data_store("queueB", "q-2")

    assert a_data["Messages"] == []
    assert b_data["Messages"] != []


def test_purge_queue_calls_write_data_store(sqs_with_messages):
    mock = sqs_with_messages
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/my-queue"

    with patch.object(mock, "_write_data_store") as mocked_write:
        mock.purge_queue(QueueUrl=queue_url)
        mocked_write.assert_called_once()

        args, kwargs = mocked_write.call_args
        assert args[0] == "my-queue"
        assert args[1] == "q-123"
        assert "Messages" in args[2]
        assert args[2]["Messages"] == []
        assert args[2]["InFlightMessages"] == []
        assert "LastPurgeTimestamp" in args[2]


def test_delete_queue_removes_metadata_and_messages(sqs_with_multiple_queues_and_messages):
    mock = sqs_with_multiple_queues_and_messages
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queueA"

    # Ensure queueA exists
    store_before = mock._read_store()
    assert "queueA" in store_before
    data_path = mock.data_path / "queueA-q-1.json"
    assert os.path.exists(data_path)

    # Delete queue
    mock.delete_queue(QueueUrl=queue_url)

    # Check metadata removed
    store_after = mock._read_store()
    assert "queueA" not in store_after
    assert "queueB" in store_after  # other queue unaffected

    # Check messages removed
    assert not os.path.exists(data_path)


def test_delete_nonexistent_queue_raises(sqs_with_multiple_queues_and_messages):
    mock = sqs_with_multiple_queues_and_messages
    with pytest.raises(Exception) as exc:
        mock.delete_queue(QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/missing-queue")
    assert "Queue missing-queue does not exist" in str(exc.value)


def test_delete_queue_does_not_affect_other_queues(sqs_with_multiple_queues_and_messages):
    mock = sqs_with_multiple_queues_and_messages
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queueA"

    # Delete queueA
    mock.delete_queue(QueueUrl=queue_url)

    # QueueB should still exist
    store_after = mock._read_store()
    assert "queueB" in store_after
    data_path_b = mock.data_path / "queueB-q-2.json"
    assert os.path.exists(data_path_b)


def test_delete_queue_calls_delete_data_store(sqs_with_multiple_queues_and_messages):
    mock = sqs_with_multiple_queues_and_messages
    queue_url = "http://sqs.local-us-east-1.pyawsmock.local/000000000000/queueA"

    with patch.object(mock, "_delete_data_store") as mocked_delete:
        mock.delete_queue(QueueUrl=queue_url)
        mocked_delete.assert_called_once_with("queueA", "q-1")


def test_send_message_basic(sqs_with_empty_store):
    queue_name = "test-queue"
    queue_url = sqs_with_empty_store.create_queue(QueueName=queue_name)["QueueUrl"]

    body = "Hello World"
    response = sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody=body)

    assert "MessageId" in response
    assert "MD5OfMessageBody" in response
    assert response["MD5OfMessageBody"] == md5(body.encode()).hexdigest()
    assert isinstance(response["MessageId"], str)
    # Check message stored in data store
    messages = sqs_with_empty_store._read_data_store(queue_name,
                                                     sqs_with_empty_store._get_queue_info(queue_url, url_mode=True)[0][
                                                         "Id"])[
        "Messages"]
    assert any(m["MessageBody"] == body for m in messages)


def test_send_message_with_delay_seconds(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="delayed-queue")["QueueUrl"]
    sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="Delayed", DelaySeconds=10)

    queue_info, _ = sqs_with_empty_store._get_queue_info(queue_url, url_mode=True)
    messages = sqs_with_empty_store._read_data_store(queue_info["Name"], queue_info["Id"])["Messages"]
    msg = messages[0]
    # Ensure VisibleAfter accounts for queue delay + message delay
    assert msg["VisibleAfter"] > datetime.now(timezone.utc).timestamp()


def test_send_message_fifo_without_deduplication(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="fifo-queue.fifo", Attributes={"FifoQueue": "true"})[
        "QueueUrl"]
    # Should fail if no MessageGroupId provided
    with pytest.raises(Exception, match="MessageGroupId is required for FIFO queues"):
        sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="FIFO Test")


def test_send_message_with_message_group_and_deduplication(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="fifo-queue.fifo", Attributes={"FifoQueue": "true"})[
        "QueueUrl"]
    response = sqs_with_empty_store.send_message(
        QueueUrl=queue_url,
        MessageBody="FIFO Test",
        MessageGroupId="group1",
        MessageDeduplicationId="dedup1"
    )
    assert "SequenceNumber" in response
    assert isinstance(response["SequenceNumber"], str)


def test_send_message_with_invalid_body(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="test-invalid")["QueueUrl"]
    invalid_body = "Invalid\x01Character"
    with pytest.raises(Exception, match="InvalidMessageContents"):
        sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody=invalid_body)


def test_send_message_with_message_attributes(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="attr-queue")["QueueUrl"]
    attrs = {
        "Attribute1": {"StringValue": "val1", "DataType": "String"},
        "Attribute2": {"StringValue": "123", "DataType": "Number"}
    }
    sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="WithAttrs", MessageAttributes=attrs)
    messages = sqs_with_empty_store._read_data_store("attr-queue",
                                                     sqs_with_empty_store._get_queue_info(queue_url, url_mode=True)[0][
                                                         "Id"])[
        "Messages"]
    msg = messages[0]
    assert msg["MessageAttributes"] == attrs


def test_send_message_with_system_attributes(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="sys-attr-queue")["QueueUrl"]
    sys_attrs = {"AWSTraceHeader": {"StringValue": "root=1-xyz", "DataType": "String"}}
    response = sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="SysAttr",
                                                 MessageSystemAttributes=sys_attrs)
    assert response.get("MD5OfMessageSystemAttributes") is not None


def test_send_message_max_size_limit(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="max-size-queue")["QueueUrl"]
    # 1 MB message
    body = "a" * 1048576
    response = sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody=body)
    assert response["MD5OfMessageBody"] == md5(body.encode()).hexdigest()

    # Exceed limit
    body = "a" * (1048576 + 1)
    with pytest.raises(Exception, match="MessageBody cannot exceed 1 MiB"):
        sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody=body)


def test_send_message_with_custom_receipt_handle(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="receipt-queue")["QueueUrl"]
    sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="CheckReceipt")
    # Ensure ReceiptHandle stored
    queue_info, _ = sqs_with_empty_store._get_queue_info(queue_url, url_mode=True)
    messages = sqs_with_empty_store._read_data_store(queue_info["Name"], queue_info["Id"])["Messages"]
    msg = messages[0]
    assert msg["MessageBody"] == "CheckReceipt"
    assert "ReceiptHandle" in msg


def test_receive_single_message(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="test-queue")["QueueUrl"]
    sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="Hello World")

    response = sqs_with_empty_store.receive_message(QueueUrl=queue_url)
    messages = response["Messages"]

    assert len(messages) == 1
    msg = messages[0]
    assert msg["Body"] == "Hello World"
    assert "ReceiptHandle" in msg
    assert msg["Attributes"]["ApproximateReceiveCount"] == "1"
    assert "MessageId" in msg


def test_receive_multiple_messages(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="multi-queue")["QueueUrl"]
    for i in range(5):
        sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody=f"Msg {i}")

    response = sqs_with_empty_store.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=3)
    messages = response["Messages"]

    assert len(messages) == 3


def test_receive_fifo_ordering(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="fifo.fifo", FifoQueue=True)["QueueUrl"]
    sqs_with_empty_store.send_message(
        QueueUrl=queue_url,
        MessageBody="Msg1",
        MessageGroupId="g1",
        MessageDeduplicationId="dedup-1"
    )
    sqs_with_empty_store.send_message(
        QueueUrl=queue_url,
        MessageBody="Msg2",
        MessageGroupId="g1",
        MessageDeduplicationId="dedup-2"
    )

    response = sqs_with_empty_store.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=2)
    messages = response["Messages"]
    assert messages[0]["MessageGroupId"] == "g1"
    assert int(messages[0]["SequenceNumber"]) < int(messages[1]["SequenceNumber"])


def test_visibility_timeout(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(
        QueueName="timeout-queue",
        Attributes={
            "VisibilityTimeout": 10
        },
    )["QueueUrl"]
    sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="Test")

    resp1 = sqs_with_empty_store.receive_message(QueueUrl=queue_url)
    assert len(resp1["Messages"]) == 1

    time.sleep(11)
    resp3 = sqs_with_empty_store.receive_message(QueueUrl=queue_url)
    assert len(resp3["Messages"]) == 1
    assert resp3["Messages"][0]["Attributes"]["ApproximateReceiveCount"] == "2"


def test_message_delay(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="delay-queue")["QueueUrl"]
    sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="Delayed", DelaySeconds=2)

    resp1 = sqs_with_empty_store.receive_message(QueueUrl=queue_url)
    assert len(resp1.get("Messages", [])) == 0  # not visible yet

    time.sleep(2.1)
    resp2 = sqs_with_empty_store.receive_message(QueueUrl=queue_url)
    assert len(resp2["Messages"]) == 1


def test_message_attributes(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="attr-queue")["QueueUrl"]
    sqs_with_empty_store.send_message(
        QueueUrl=queue_url,
        MessageBody="AttrTest",
        MessageAttributes={"foo": {"StringValue": "bar", "DataType": "String"}}
    )

    resp = sqs_with_empty_store.receive_message(
        QueueUrl=queue_url, MessageAttributeNames=["foo"]
    )
    msg = resp["Messages"][0]
    assert "foo" in msg["MessageAttributes"]


def test_system_attributes(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="sysattr-queue")["QueueUrl"]
    sqs_with_empty_store.send_message(QueueUrl=queue_url, MessageBody="SysAttrTest")

    resp = sqs_with_empty_store.receive_message(
        QueueUrl=queue_url,
        MessageSystemAttributeNames=["All"]
    )
    msg = resp["Messages"][0]
    assert "ApproximateReceiveCount" in msg["Attributes"]
    assert "SentTimestamp" in msg["Attributes"]


def test_receive_request_attempt_id(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="fifo-test.fifo", FifoQueue=True)["QueueUrl"]
    sqs_with_empty_store.send_message(
        QueueUrl=queue_url, MessageBody="RetryTest", MessageGroupId="g1", MessageDeduplicationId="dedup-1"
    )

    attempt_id = "attempt123"
    resp1 = sqs_with_empty_store.receive_message(QueueUrl=queue_url, ReceiveRequestAttemptId=attempt_id)
    resp2 = sqs_with_empty_store.receive_message(QueueUrl=queue_url, ReceiveRequestAttemptId=attempt_id)

    assert resp1["Messages"][0]["ReceiptHandle"] == resp2["Messages"][0]["ReceiptHandle"]


def test_receive_empty_queue(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="empty-queue")["QueueUrl"]
    resp = sqs_with_empty_store.receive_message(QueueUrl=queue_url)
    assert resp.get("Messages", []) == []


def test_delete_message_removes_from_messages(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="del-test")["QueueUrl"]
    queue_info, _ = sqs_with_empty_store._get_queue_info(queue_url, url_mode=True)
    queue_id = queue_info["Id"]
    msg = make_message()
    sqs_with_empty_store._write_data_store("del-test", queue_id, {"Messages": [msg]})

    # Delete
    sqs_with_empty_store.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    store = sqs_with_empty_store._read_data_store("del-test", queue_id)
    assert len(store["Messages"]) == 0


def test_delete_message_removes_from_inflight(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="del-inflight")["QueueUrl"]
    queue_info, _ = sqs_with_empty_store._get_queue_info(queue_url, url_mode=True)
    queue_id = queue_info["Id"]
    msg = make_message()
    sqs_with_empty_store._write_data_store("del-inflight", queue_id, {
        "Messages": [msg],
        "InFlightMessages": {msg["ReceiptHandle"]: msg}
    })

    sqs_with_empty_store.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    store = sqs_with_empty_store._read_data_store("del-inflight", queue_id)
    assert msg["ReceiptHandle"] not in store.get("InFlightMessages", {})


def test_delete_message_removes_from_receive_attempts(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="del-attempts")["QueueUrl"]
    queue_info, _ = sqs_with_empty_store._get_queue_info(queue_url, url_mode=True)
    queue_id = queue_info["Id"]
    msg = make_message()
    attempt_key = f"{msg['MessageId']}_attempt1"
    sqs_with_empty_store._write_data_store("del-attempts", queue_id, {
        "Messages": [msg],
        "ReceiveRequestAttempts": {attempt_key: msg}
    })

    sqs_with_empty_store.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    store = sqs_with_empty_store._read_data_store("del-attempts", queue_id)
    assert attempt_key not in store.get("ReceiveRequestAttempts", {})


def test_delete_message_invalid_receipt_handle_raises(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="invalid-handle")["QueueUrl"]
    with pytest.raises(ValueError, match="ReceiptHandle is invalid or message already deleted"):
        sqs_with_empty_store.delete_message(QueueUrl=queue_url, ReceiptHandle="nonexistent")


def test_delete_message_missing_receipt_handle_raises(sqs_with_empty_store):
    queue_url = sqs_with_empty_store.create_queue(QueueName="missing-handle")["QueueUrl"]
    with pytest.raises(ValueError, match="ReceiptHandle is required"):
        sqs_with_empty_store.delete_message(QueueUrl=queue_url)
