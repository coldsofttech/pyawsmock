# 📬 MockSQS - Local SQS Mock

> **MockSQS** is a local, file-based mock of AWS SQS (Simple Queue Service). It allows developers to simulate SQS
> queues,
> message sending, receiving, and deletion without interacting with real AWS services. Ideal for **unit tests, CI/CD
pipelines, and local development**.

---

## ⚡ Highlights

- ✅ Fully **local, file-based** SQS mock.
- 🗂 Supports **standard and FIFO queues**.
- ✉️ Supports **send, receive, delete messages**.
- 🔄 Tracks **message visibility, delays, and deduplication**.
- 🛠 Stores queues and messages in **gzip-compressed JSON**.
- ⚠️ Provides **mock-specific warnings and simplified behavior**.

---

## 🌿 Overview

`MockSQS` simulates AWS SQS functionality locally:

- Create, list, modify, and delete **queues**.
- Send, receive, and delete **messages**.
- Supports **FIFO queues** with deduplication.
- Tracks **message visibility timeout**, delays, and receive attempts.
- Provides **Queue URL and ARN** metadata.

> ⚠️ Note: This is a **mock implementation**. It does not connect to AWS and does not provide guaranteed behavior like
> AWS SQS.

---

## 🚀 Key Features

| Feature          | Description                                                             |
|------------------|-------------------------------------------------------------------------|
| Queue Creation   | Create standard and FIFO queues with attributes and tags.               |
| Queue URL        | Retrieve queue URLs for messaging operations.                           |
| Queue Attributes | Get or set queue-specific attributes.                                   |
| Queue Listing    | List queues with optional prefix filtering and pagination.              |
| Message Handling | Send, receive, delete messages with visibility and delay simulation.    |
| FIFO Support     | Deduplication via `MessageDeduplicationId` or content-based hash.       |
| Local Storage    | All queues and messages stored as compressed JSON locally.              |
| Mock Behavior    | Simplified HTTP domain support, warnings for unsupported AWS behaviors. |

---

## 🏗️ Instantiation

```python
from pyawsmock import configure_mock, client

# Configure local mock (persistent storage)
configure_mock(mode="persistent", path="./local_sqs")

# Create MockSQS client
sqs = client("sqs", region_name="local-eu-west-1")
```

> 🔑 `region_name` must be `local-` for mock behavior; otherwise it delegates to real AWS.

---

## 🛠️ Methods & Examples

### `create_queue`

```python
resp = sqs.create_queue(
    QueueName="test-queue.fifo",
    Attributes={"FifoQueue": "true", "VisibilityTimeout": "45"},
)
print(resp)
```

Returns:

```json
{
  "QueueUrl": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo"
}
```

---

### `get_queue_url`

```python
sqs.get_queue_url(QueueName="test-queue.fifo")
```

Returns:

```json
{
  "QueueUrl": "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo"
}
```

---

### `set_queue_attributes`

```python
sqs.set_queue_attributes(
    QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo",
    Attributes={"VisibilityTimeout": "60"}
)
```

Updates queue attributes locally.

---

### `get_queue_attributes`

```python
sqs.get_queue_attributes(
    QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo",
    AttributeNames=["VisibilityTimeout", "DelaySeconds"]
)
```

Returns:

```json
{
  "Attributes": {
    "VisibilityTimeout": "60",
    "DelaySeconds": "0"
  }
}
```

---

### `list_queues`

```python
sqs.list_queues(QueueNamePrefix="test")
```

Returns:

```json
{
  "QueueUrls": [
    "http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo"
  ],
  "NextToken": null
}
```

---

### `purge_queue`

```python
sqs.purge_queue(
    QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo"
)
```

Clears all messages in the queue.

---

### `delete_queue`

```python
sqs.delete_queue(
    QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo"
)
```

Removes the queue and associated message data.

---

### `send_message`

```python
sqs.send_message(
    QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo",
    MessageBody="Hello World",
    MessageGroupId="group1",
    MessageDeduplicationId="msg-1"
)
```

Returns:

```json
{
  "MessageId": "uuid",
  "MD5OfMessageBody": "md5hash",
  "MD5OfMessageAttributes": null,
  "MD5OfMessageSystemAttributes": null,
  "SequenceNumber": "1"
}
```

---

### `receive_message`

```python
sqs.receive_message(
    QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo",
    MaxNumberOfMessages=2,
    MessageAttributeNames=["All"],
    MessageSystemAttributeNames=["SentTimestamp"]
)
```

Returns:

```json
{
  "Messages": [
    {
      "MessageId": "uuid",
      "ReceiptHandle": "uuid",
      "Body": "Hello World",
      "Attributes": {
        "SentTimestamp": "timestamp",
        "ApproximateReceiveCount": "1"
      },
      "MessageAttributes": {},
      "SequenceNumber": "1",
      "MessageGroupId": "group1",
      "MessageDeduplicationId": "msg-1"
    }
  ]
}
```

---

### `delete_message`

```python
sqs.delete_message(
    QueueUrl="http://sqs.local-us-east-1.pyawsmock.local/000000000000/test-queue.fifo",
    ReceiptHandle="uuid"
)
```

Removes a message from the queue by its `ReceiptHandle`.

---

## ⚠️ Limitations (Mock-Specific)

- Only **local JSON storage**; no actual AWS network calls.
- FIFO deduplication simulated; no guarantee of exact AWS behavior.
- Delays and visibility timeouts are **approximate**; not real-time.
- Only **HTTP endpoints** supported for local queues.
- No AWS IAM, encryption (SSE-KMS), or dead-letter queue enforcement.
- Paginated listing supports basic `NextToken` but not AWS-style token expiration.
- Queue attributes not fully validated against all AWS rules.