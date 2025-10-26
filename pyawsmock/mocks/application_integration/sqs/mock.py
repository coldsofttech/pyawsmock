import json
import os
import re
import time
import uuid
import warnings
from datetime import datetime, timezone
from hashlib import sha256, md5
from typing import Dict, Any

from pyawsmock.mocks.base_mock import MockBase
from pyawsmock.mocks.store_utils import StoreUtils


class MockSQSValidator:
    TAG_PATTERN = re.compile(r"^[\w\s_.:/=+\-@]+$")
    QUEUE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
    QUEUE_URL_PATTERN = re.compile(r"^http://sqs\.[a-z0-9-]+\.pyawsmock\.local/\d{12}/[\w.-]+$")
    MESSAGE_ATTRIBUTE_NAME_PATTERN = re.compile(r"^(?!AWS\.|Amazon\.)(?!\.)(?!.*\.\.)(?!.*\.$)[A-Za-z0-9_\-\.]{1,256}$")
    MESSAGE_BODY_PATTERN = re.compile(
        r"[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]|[\U00010000-\U0010FFFF]",
        flags=re.UNICODE
    )

    @staticmethod
    def _raise_if(condition, message):
        if condition:
            raise ValueError(message)

    @classmethod
    def queue_name(cls, name: str, fifo: bool = False):
        cls._raise_if(not name or not name.strip(), "QueueName is required")
        cls._raise_if(len(name) > 80, "QueueName should be max of 80 characters")
        if fifo:
            cls._raise_if(not name.endswith(".fifo"), "QueueName must end with '.fifo' for FIFO Queues")
            base_name = name[:-5]
        else:
            base_name = name
        cls._raise_if(
            not re.fullmatch(cls.QUEUE_NAME_PATTERN, base_name),
            "QueueName can only contain alphanumeric characters"
        )

    @classmethod
    def queue_url(cls, url: str):
        cls._raise_if(not url, "QueueUrl is required")
        cls._raise_if(not re.fullmatch(cls.QUEUE_URL_PATTERN, url), "Invalid QueueUrl")

    @classmethod
    def attribute_names(cls, attrs: list):
        valid_keys = [
            "DelaySeconds", "MaximumMessageSize", "MessageRetentionPeriod", "Policy",
            "ReceiveMessageWaitTimeSeconds", "VisibilityTimeout", "RedrivePolicy", "RedriveAllowPolicy",
            "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds", "SqsManagedSseEnabled", "FifoQueue",
            "ContentBasedDeduplication", "DeduplicationScope", "FifoThroughputLimit", "QueueArn", "All"
        ]
        for key in attrs:
            cls._raise_if(key not in valid_keys, f"Invalid Attribute: {key}")

    @classmethod
    def attributes(cls, attr: dict, required: bool = False):
        valid_keys = {
            "DelaySeconds", "MaximumMessageSize", "MessageRetentionPeriod", "Policy",
            "ReceiveMessageWaitTimeSeconds", "VisibilityTimeout", "RedrivePolicy", "RedriveAllowPolicy",
            "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds", "SqsManagedSseEnabled", "FifoQueue",
            "ContentBasedDeduplication", "DeduplicationScope", "FifoThroughputLimit", "QueueArn", "All"
        }
        int_fields = {
            "DelaySeconds": (0, 900),
            "MaximumMessageSize": (1024, 1048576),
            "MessageRetentionPeriod": (60, 1209600),
            "ReceiveMessageWaitTimeSeconds": (0, 20),
            "VisibilityTimeout": (0, 43200),
            "KmsDataKeyReusePeriodSeconds": (60, 86400),
        }
        if required:
            cls._raise_if(not attr, "Attributes is required")
            cls._raise_if(not isinstance(attr, dict), "Attributes must be a dict")
            for key in attr.keys():
                cls._raise_if(key not in valid_keys, f"Invalid Attribute: {key}")
                cls._raise_if(key == "QueueArn", "Cannot modify read-only attribute: QueueArn")
        for key, value in (attr or {}).items():
            if key in int_fields:
                try:
                    val = int(value)
                except ValueError:
                    cls._raise_if(True, f"{key} must be an integer.")
                low, high = int_fields[key]
                cls._raise_if(not (low <= val <= high), f"{key} must be between {low} and {high}.")
            elif key == "RedrivePolicy":
                try:
                    rp = json.loads(value)
                    cls._raise_if(
                        "deadLetterTargetArn" not in rp or "maxReceiveCount" not in rp,
                        "RedrivePolicy must contain 'deadLetterTargetArn' and 'maxReceiveCount'."
                    )
                except json.JSONDecodeError:
                    cls._raise_if(True, "RedrivePolicy must be a valid JSON string.")
            elif key in ("FifoQueue", "ContentBasedDeduplication"):
                cls._raise_if(
                    str(value).lower() not in ("true", "false"),
                    f"{key} must be 'true' or 'false'."
                )
            elif key == "DeduplicationScope":
                cls._raise_if(
                    value not in ("messageGroup", "queue"),
                    "DeduplicationScope must be 'messageGroup' or 'queue'."
                )
            elif key == "FifoThroughputLimit":
                cls._raise_if(
                    value not in ("perQueue", "perMessageGroupId"),
                    "FifoThroughputLimit must be 'perQueue' or 'perMessageGroupId'."
                )

    @classmethod
    def message(cls, body, is_fifo, group_id, delay_seconds):
        cls._raise_if(not body, "MessageBody is required")
        cls._raise_if(cls.MESSAGE_BODY_PATTERN.search(body), "InvalidMessageContents")
        cls._raise_if(is_fifo and not group_id, "MessageGroupId is required for FIFO queues")
        cls._raise_if(is_fifo and delay_seconds, "DelaySeconds per message is only allowed for standard queues")
        cls._raise_if(len(body.encode("utf-8")) > 1048576, "MessageBody cannot exceed 1 MiB")

    @classmethod
    def message_attributes(cls, attrs, list_type: bool = False):
        for name, attr in attrs.items():
            cls._raise_if(
                not cls.MESSAGE_ATTRIBUTE_NAME_PATTERN.match(name),
                f"Invalid MessageAttributeName: {name}"
            )
            if not list_type:
                cls._raise_if(
                    "DataType" not in attr or not attr["DataType"],
                    f"MessageAttribute {name} must have a DataType"
                )
                cls._raise_if(
                    "StringValue" not in attr and "BinaryValue" not in attr,
                    f"MessageAttribute {name} must have StringValue or BinaryValue"
                )

    @classmethod
    def system_attributes(cls, attrs):
        for name in (attrs or []):
            cls._raise_if(
                name != "All" and name not in [
                    "All", "ApproximateFirstReceiveTimestamp", "ApproximateReceiveCount",
                    "AWSTraceHeader", "SenderId", "SentTimestamp", "SequenceNumber",
                    "MessageDeduplicationId", "MessageGroupId"
                ],
                f"Invalid MessageSystemAttributeName: {name}"
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


Validator = MockSQSValidator


class MockSQS(MockBase):
    _supported_methods = [
        "create_queue",
        "get_queue_url",
        "set_queue_attributes",
        "get_queue_attributes",
        "list_queues",
        "purge_queue",
        "delete_queue",
        "send_message",
        "receive_message",
        "delete_message",
    ]

    def __init__(self, base_path, region_name):
        self.region_name = region_name
        self.store_path = base_path / region_name / "sqs_queues.json"
        self.data_path = base_path / region_name / "SQS"
        os.makedirs(self.data_path, exist_ok=True)
        self.store_lock_path = f"{self.store_path}.lock"
        self.data_lock_path = f"{self.data_path}.lock"
        os.makedirs(self.store_path.parent, exist_ok=True)
        if not self.store_path.exists():
            self._write_store({})

    def _read_store(self):
        return StoreUtils.read_json_gzip(self.store_path)

    def _write_store(self, data):
        StoreUtils.write_json_gzip(self.store_path, data, self.store_lock_path)

    def _read_data_store(self, name: str, id_: str):
        return StoreUtils.read_json_gzip(self.data_path / f"{name}-{id_}.json")

    def _write_data_store(self, name: str, id_: str, data):
        StoreUtils.write_json_gzip(self.data_path / f"{name}-{id_}.json", data, self.data_lock_path)

    def _delete_data_store(self, name: str, id_: str):
        path = self.data_path / f"{name}-{id_}.json"
        if os.path.exists(path):
            os.remove(path)

    def _get_queue_info(self, name: str, owner: str = None, url_mode: bool = False):
        if url_mode:
            Validator.queue_url(name)
            parts = name.split("/")
            name, owner = parts[-1], parts[-2]
        if not name:
            raise ValueError("QueueName is required")
        Validator.queue_name(name, name.endswith(".fifo"))
        data_store = self._read_store()
        if name not in data_store:
            raise ValueError(f"Queue {name} does not exist")
        queue_info = data_store[name]
        if owner:
            if queue_info["Owner"] != owner:
                raise ValueError(f"Queue {name} does not belong to {owner}")
        return queue_info, data_store

    def _paginate_queues(self, items, max_results=None, next_token=None):
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

    def _resolve_deduplication_id(self, body, dedup_id, content_dedup):
        if dedup_id:
            return dedup_id
        if content_dedup:
            return sha256(body.encode("utf-8")).hexdigest()
        raise ValueError("MessageDeduplicationId is required for FIFO queues without ContentBasedDeduplication")

    def _is_duplicate_message(self, messages, dedup_id):
        return any(m.get("MessageDeduplicationId") == dedup_id for m in messages)

    def create_queue(self, **kwargs) -> Dict[str, Any]:
        queue_name = kwargs.get("QueueName")
        attributes = kwargs.get("Attributes")
        tags = kwargs.get("Tags")

        if not queue_name:
            raise ValueError("QueueName is required")
        if queue_name.endswith(".fifo"):
            if attributes:
                attributes["FifoQueue"] = "true"
            else:
                attributes = {"FifoQueue": "true"}

        data_store = self._read_store()
        if queue_name in data_store:
            raise ValueError(f"Queue {queue_name} already exists.")
        Validator.queue_name(
            queue_name,
            str((attributes or {}).get("FifoQueue", "false")).lower() == "true"
        )
        Validator.attributes(attributes)
        if attributes:
            if attributes.get("FifoQueue", "false") == "true" and not queue_name.endswith(".fifo"):
                raise ValueError(f"Queue {queue_name} does not have .fifo queue.")
        if tags:
            Validator.tags(tags)

        warnings.warn("Only HTTP domains are supported in local mock mode.")
        queue_id = str(uuid.uuid4())[:8]
        queue_arn = f"arn:mock:sqs:{self.region_name}:000000000000:{queue_name}"
        queue_path = self.data_path / f"{queue_name}_{queue_id}.json"
        self._write_data_store(queue_name, queue_id, {
            "Messages": [],
            "InFlightMessages": [],
            "LastPurgeTimestamp": None,
            "ReceiveRequestAttempts": {}
        })
        queue_attributes = {
            "DelaySeconds": "0",
            "MaximumMessageSize": "262144",
            "MessageRetentionPeriod": "345600",
            "ReceiveMessageWaitTimeSeconds": "0",
            "VisibilityTimeout": "30",
            "FifoQueue": "true" if queue_name.endswith(".fifo") else "false",
            "ContentBasedDeduplication": "false",
            "QueueArn": queue_arn,
            "ApproximateNumberOfMessages": "0",
            "ApproximateNumberOfMessagesNotVisible": "0",
            "ApproximateNumberOfMessagesDelayed": "0",
            "KmsDataKeyReusePeriodSeconds": "300",
            "SqsManagedSseEnabled": "false",
        }
        if attributes:
            queue_attributes.update(attributes)
        data_store[queue_name] = {
            "Name": queue_name,
            "Attributes": queue_attributes,
            "Tags": tags or [],
            "Id": queue_id,
            "Owner": "000000000000",
            "Url": f"http://sqs.{self.region_name}.{self._mock_domain}/000000000000/{queue_name}",
            "CreatedTime": datetime.now(timezone.utc).isoformat(),
            "Arn": queue_arn,
            "SQSPath": str(queue_path.relative_to(self.data_path)),
        }
        self._write_store(data_store)

        return {
            "QueueUrl": data_store[queue_name]["Url"],
        }

    def get_queue_url(self, **kwargs) -> Dict[str, Any]:
        queue_name = kwargs.get("QueueName")
        queue_owner = kwargs.get("QueueOwnerAWSAccountId")
        queue_info, data_store = self._get_queue_info(queue_name, queue_owner)

        return {
            "QueueUrl": queue_info["Url"],
        }

    def set_queue_attributes(self, **kwargs):
        queue_url = kwargs.get("QueueUrl")
        attributes = kwargs.get("Attributes")
        Validator.attributes(attributes, True)
        queue_info, data_store = self._get_queue_info(queue_url, url_mode=True)
        queue_attributes = queue_info.setdefault("Attributes", {})
        queue_attributes.update(attributes)
        queue_info["LastModifiedTime"] = datetime.now(timezone.utc).isoformat()
        data_store[queue_info["Name"]] = queue_info
        self._write_store(data_store)

    def get_queue_attributes(self, **kwargs) -> Dict[str, Any]:
        queue_url = kwargs.get("QueueUrl")
        attribute_names = kwargs.get("AttributeNames")
        Validator.attribute_names(attribute_names)
        queue_info, data_store = self._get_queue_info(queue_url, url_mode=True)
        queue_attributes = queue_info.setdefault("Attributes", {})
        if not attribute_names or "All" in attribute_names:
            result = queue_attributes.copy()
        else:
            result = {k: v for k, v in queue_attributes.items() if k in attribute_names}

        return {
            "Attributes": result,
        }

    def list_queues(self, **kwargs) -> Dict[str, Any]:
        queue_prefix = kwargs.get("QueueNamePrefix")
        next_token = kwargs.get("NextToken")
        max_results = kwargs.get("MaxResults")
        queues = list(self._read_store().values())
        if queue_prefix:
            queues = [
                q for q in queues
                if q["Name"].startswith(queue_prefix)
            ]
        queues.sort(key=lambda q: q["Name"])
        page, next_token = self._paginate_queues(queues, max_results, next_token)
        response_list = [
            p["Url"] for p in page
        ]

        return {
            "QueueUrls": response_list,
            "NextToken": next_token,
        }

    def purge_queue(self, **kwargs):
        queue_url = kwargs.get("QueueUrl")
        queue_info, data_store = self._get_queue_info(queue_url, url_mode=True)
        self._write_data_store(queue_info["Name"], queue_info["Id"], {
            "Messages": [],
            "InFlightMessages": [],
            "LastPurgeTimestamp": datetime.now(timezone.utc).isoformat(),
            "ReceiveRequestAttempts": {}
        })

    def delete_queue(self, **kwargs):
        queue_url = kwargs.get("QueueUrl")
        queue_info, data_store = self._get_queue_info(queue_url, url_mode=True)
        self._delete_data_store(queue_info["Name"], queue_info["Id"])
        del data_store[queue_info["Name"]]
        self._write_store(data_store)

    def send_message(self, **kwargs) -> Dict[str, Any]:
        queue_url = kwargs.get("QueueUrl")
        queue_info, _ = self._get_queue_info(queue_url, url_mode=True)
        queue_attributes = queue_info.setdefault("Attributes", {})

        message_body = kwargs.get("MessageBody")
        message_delay = kwargs.get("DelaySeconds", 0)
        message_attributes = kwargs.get("MessageAttributes", {})
        system_attributes = kwargs.get("MessageSystemAttributes", {})
        message_dedup_id = kwargs.get("MessageDeduplicationId")
        message_group_id = kwargs.get("MessageGroupId")

        is_fifo = queue_attributes.get("FifoQueue", "false").lower() == "true"
        content_dedup = queue_attributes.get("ContentBasedDeduplication", "false").lower() == "true"

        Validator.message(message_body, is_fifo, message_group_id, message_delay)
        Validator.message_attributes(message_attributes)
        Validator.system_attributes(list(system_attributes or {}))

        msg_store = self._read_data_store(queue_info["Name"], queue_info["Id"])
        messages = msg_store.setdefault("Messages", [])

        if is_fifo:
            message_dedup_id = self._resolve_deduplication_id(message_body, message_dedup_id, content_dedup)
            if self._is_duplicate_message(messages, message_dedup_id):
                existing_msg = next(m for m in messages if m.get("MessageDeduplicationId") == message_dedup_id)
                return {
                    "MessageId": existing_msg["MessageId"],
                    "MD5OfMessageBody": existing_msg["MD5OfMessageBody"],
                    "MD5OfMessageAttributes": existing_msg.get("MD5OfMessageAttributes"),
                    "MD5OfMessageSystemAttributes": existing_msg.get("MD5OfMessageSystemAttributes"),
                    "SequenceNumber": existing_msg.get("SequenceNumber"),
                }

        queue_delay = int(queue_attributes.get("DelaySeconds", 0))
        effective_delay = int(message_delay) if message_delay is not None else queue_delay
        now = datetime.now(timezone.utc)
        sent_timestamp = int(now.timestamp() * 1000)
        visible_after = now.timestamp() + effective_delay

        message = {
            "MessageId": str(uuid.uuid4()),
            "MessageBody": message_body,
            "MessageAttributes": message_attributes,
            "MessageSystemAttributes": system_attributes,
            "MD5OfMessageBody": md5(message_body.encode("utf-8")).hexdigest(),
            "MD5OfMessageAttributes": (
                md5(json.dumps(message_attributes, sort_keys=True).encode("utf-8")).hexdigest()
                if message_attributes else None
            ),
            "MD5OfMessageSystemAttributes": (
                md5(json.dumps(system_attributes, sort_keys=True).encode("utf-8")).hexdigest()
                if system_attributes else None
            ),
            "MessageDeduplicationId": message_dedup_id,
            "MessageGroupId": message_group_id,
            "DelaySeconds": message_delay,
            "SentTimestamp": sent_timestamp,
            "SequenceNumber": str(len(messages) + 1) if is_fifo else None,
            "ApproximateReceiveCount": 0,
            "VisibleAfter": visible_after,
            "ReceiptHandle": str(uuid.uuid4()),
        }
        messages.append(message)
        msg_store["Messages"] = messages
        self._write_data_store(queue_info["Name"], queue_info["Id"], msg_store)

        return {
            "MessageId": message["MessageId"],
            "MD5OfMessageBody": message["MD5OfMessageBody"],
            "MD5OfMessageAttributes": message.get("MD5OfMessageAttributes"),
            "MD5OfMessageSystemAttributes": message.get("MD5OfMessageSystemAttributes"),
            "SequenceNumber": message.get("SequenceNumber"),
        }

    def receive_message(self, **kwargs) -> Dict[str, Any]:
        queue_url = kwargs.get("QueueUrl")
        message_attributes = kwargs.get("MessageAttributeNames", [])
        system_attributes = kwargs.get("MessageSystemAttributeNames", [])
        max_no_of_messages = min(kwargs.get("MaxNumberOfMessages", 1), 10)

        queue_info, _ = self._get_queue_info(queue_url, url_mode=True)
        queue_attributes = queue_info.setdefault("Attributes", {})
        is_fifo = queue_attributes.get("FifoQueue", "false") == "true"

        Validator.message_attributes({name: {} for name in message_attributes}, True)
        Validator.system_attributes(system_attributes)

        raw_vt = queue_attributes.get("VisibilityTimeout", 30)
        try:
            visibility_timeout = int(float(raw_vt))
        except (ValueError, TypeError):
            visibility_timeout = 30

        wait_time = int(kwargs.get("WaitTimeSeconds", queue_attributes.get("ReceiveMessageWaitTimeSeconds", 0)))
        end_time = time.time() + wait_time

        selected_messages = []
        attempt_id = kwargs.get("ReceiveRequestAttemptId")
        while time.time() <= end_time and len(selected_messages) < max_no_of_messages:
            msg_store = self._read_data_store(queue_info["Name"], queue_info["Id"])
            messages = msg_store.get("Messages", [])
            receive_attempts = msg_store.setdefault("ReceiveRequestAttempts", {})
            now_ts = time.time()

            if attempt_id:
                for m in messages:
                    key = f"{m['MessageId']}_{attempt_id}"
                    if key in receive_attempts:
                        selected_messages.append(receive_attempts[key])
                        break
                if selected_messages:
                    return {
                        "Messages": selected_messages
                    }

            available_msgs = [m for m in messages if float(m.get("VisibleAfter", 0)) <= now_ts + 0.01]
            if not available_msgs:
                time.sleep(0.1)
                continue

            if is_fifo:
                available_msgs.sort(key=lambda x: int(x.get("SequenceNumber", 0)))

            for m in available_msgs[:max_no_of_messages - len(selected_messages)]:
                m["VisibleAfter"] = float(now_ts + visibility_timeout)
                m["ApproximateReceiveCount"] = m.get("ApproximateReceiveCount", 0) + 1

                msg_response = {
                    "MessageId": m["MessageId"],
                    "ReceiptHandle": m["ReceiptHandle"],
                    "MD5OfBody": md5(m["MessageBody"].encode('utf-8')).hexdigest(),
                    "Body": m["MessageBody"],
                    "Attributes": {  # System attributes
                        "ApproximateReceiveCount": str(m["ApproximateReceiveCount"]),
                        "SentTimestamp": str(m["SentTimestamp"]),
                    },
                    "MD5OfMessageAttributes": md5(json.dumps(m["MessageAttributes"]).encode('utf-8')).hexdigest(),
                    "MessageAttributes": m["MessageAttributes"],
                }
                if attempt_id:
                    key = f"{m['MessageId']}_{attempt_id}"
                    receive_attempts[key] = msg_response

                if is_fifo:
                    msg_response["MessageGroupId"] = m["MessageGroupId"]
                    msg_response["MessageDeduplicationId"] = m["MessageDeduplicationId"]
                    msg_response["SequenceNumber"] = m["SequenceNumber"]

                if system_attributes:
                    if "All" in system_attributes:
                        msg_response["Attributes"] = msg_response["Attributes"]
                    else:
                        msg_response["Attributes"] = {
                            k: v for k, v in msg_response["Attributes"].items() if k in system_attributes
                        }

                if message_attributes:
                    msg_response["MessageAttributes"] = {
                        k: v for k, v in msg_response["MessageAttributes"].items() if k in message_attributes
                    }
                selected_messages.append(msg_response)

            msg_store["Messages"] = messages
            msg_store["ReceiveRequestAttempts"] = receive_attempts
            self._write_data_store(queue_info["Name"], queue_info["Id"], msg_store)
            if selected_messages:
                break

        return {
            "Messages": selected_messages
        }

    def delete_message(self, **kwargs):
        queue_url = kwargs.get("QueueUrl")
        queue_info, data_store = self._get_queue_info(queue_url, url_mode=True)
        receipt_handle = kwargs.get("ReceiptHandle")
        if not receipt_handle:
            raise ValueError("ReceiptHandle is required")
        msg_store = self._read_data_store(queue_info["Name"], queue_info["Id"])
        messages = msg_store.setdefault("Messages", [])
        in_flight = msg_store.setdefault("InFlightMessages", {})
        receive_attempts = msg_store.setdefault("ReceiveRequestAttempts", {})

        message_index = None
        for i, msg in enumerate(messages):
            if msg.get("ReceiptHandle") == receipt_handle:
                message_index = i
                break
        if message_index is None:
            raise ValueError("ReceiptHandle is invalid or message already deleted")
        messages.pop(message_index)

        in_flight_keys_to_remove = [
            key for key, m in in_flight.items()
            if m.get("ReceiptHandle") == receipt_handle
        ]
        for key in in_flight_keys_to_remove:
            in_flight.pop(key)

        attempt_keys_to_remove = [
            key for key, m in receive_attempts.items()
            if m.get("ReceiptHandle") == receipt_handle
        ]
        for key in attempt_keys_to_remove:
            receive_attempts.pop(key)

        self._write_data_store(
            queue_info["Name"], queue_info["Id"], {
                **msg_store,
                "Messages": messages,
                "InFlightMessages": in_flight,
                "ReceiveRequestAttempts": receive_attempts,
            }
        )
