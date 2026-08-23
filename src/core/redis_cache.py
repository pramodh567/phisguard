import os
import json
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=0,
        decode_responses=True,
        socket_connect_timeout=2
    )
    redis_client.ping()
except Exception:
    redis_client = None

def get_cached_scan(url: str):
    """Retrieves cached scan result in < 1ms."""
    if not redis_client:
        return None
    try:
        cached = redis_client.get(f"scan:{url}")
        return json.loads(cached) if cached else None
    except Exception:
        return None

def set_cached_scan(url: str, scan_data: dict, ttl_seconds: int = 1800):
    """Caches scan result with default 30-minute expiration."""
    if not redis_client:
        return
    try:
        redis_client.setex(f"scan:{url}", ttl_seconds, json.dumps(scan_data))
    except Exception:
        pass