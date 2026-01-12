"""
Configuration constants for zero-trust framework

These constants define default values for the framework components.
Override these in your application configuration as needed.
"""

# Authentication constants
DEFAULT_REQUIRED_FACTORS = 2
SESSION_TIMEOUT_SECONDS = 3600  # 1 hour
SESSION_CLEANUP_AGE_SECONDS = 300  # 5 minutes
MIN_TRUST_SCORE = 0.5

# Verification constants
MAX_PAYLOAD_SIZE_BYTES = 1000000  # 1 MB
RATE_LIMIT_REQUESTS = 50
RATE_LIMIT_WINDOW_SECONDS = 60
REVERIFICATION_INTERVAL_SECONDS = 300  # 5 minutes

# Monitoring constants
FAILED_LOGIN_ALERT_THRESHOLD = 5
ALERT_TIME_WINDOW_SECONDS = 300  # 5 minutes

# Authorization constants
DEFAULT_POLICY_CACHE_TTL = 300  # 5 minutes

# Network constants
DEFAULT_SAME_SEGMENT_BYPASS = True
