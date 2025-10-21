class MockS3TransferConfig:
    def __init__(
            self,
            multipart_threshold=8 * 1024 * 1024,
            max_concurrency=10,
            multipart_chunksize=8 * 1024 * 1024,
            num_download_attempts=5,
            max_io_queue=100,
            io_chunksize=256 * 1024,
            use_threads=True,
            max_bandwidth=None,
            preferred_transfer_client="auto",
    ):
        self.multipart_threshold = multipart_threshold
        self.max_concurrency = max_concurrency
        self.multipart_chunksize = multipart_chunksize
        self.num_download_attempts = num_download_attempts
        self.max_io_queue = max_io_queue
        self.io_chunksize = io_chunksize
        self.use_threads = use_threads
        self.max_bandwidth = max_bandwidth
        self.preferred_transfer_client = preferred_transfer_client


class MockS3Transfer:
    def __init__(self, client, config=None):
        self.client = client
        self.config = config

    def upload_file(self, filename, bucket, key, extra_args=None, callback=None):
        return self.client.upload_file(
            Filename=filename,
            Bucket=bucket,
            Key=key,
            ExtraArgs=extra_args,
            Callback=callback,
            Config=self.config,
        )

    def download_file(self, bucket, key, filename, extra_args=None, callback=None):
        return self.client.download_file(
            Bucket=bucket,
            Key=key,
            Filename=filename,
            ExtraArgs=extra_args,
            Callback=callback,
            Config=self.config,
        )
