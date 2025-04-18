from datetime import datetime
from typing import Any, Dict, Optional
import json

def datetime_handler(obj: Any) -> str:
    """Handle datetime serialization"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

def serialize_response(data: Dict) -> bytes:
    """Serialize response data to JSON bytes"""
    return json.dumps(data, default=datetime_handler).encode('utf-8')

def format_datetime(dt: Optional[datetime]) -> str:
    """Format datetime for display"""
    if dt is None:
        return 'Never'
    return dt.strftime('%Y-%m-%d %H:%M:%S')