import io


class MockStreamingBody(io.BytesIO):
    def __init__(self, content: bytes):
        super().__init__(content)
        self._total_bytes = len(content)
