"""Fixture response bounds; request and tool-argument limits are independent."""
RAW_SSE_BYTES=8*1024*1024
PROVIDER_WIRE_BYTES=12*1024*1024
RELAY_REPLY_BYTES=12*1024*1024
REQUEST_FRAME_BYTES=65536
RELAY_READ_TIMEOUT_SECONDS=90

def reply_fits(value):return isinstance(value,int) and 0<=value<=RELAY_REPLY_BYTES
