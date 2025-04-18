from enum import Enum
from datetime import datetime
import json

class MessageType(Enum):
    NEGOTIATE = 1
    CHALLENGE = 2
    AUTHENTICATE = 3
    VIEW_LOGS = 4
    VIEW_USERS = 5
    CHANGE_USERNAME = 6
    ADD_USER = 7
    REMOVE_USER = 8
    UPDATE_USER = 9
    CHANGE_PASSWORD = 10

class BaseMessage:
    """Base class for all messages"""
    def __init__(self, message_type: MessageType):
        self.message_type = message_type
        self.timestamp = datetime.utcnow().timestamp()
        self.session_id = None

    def to_dict(self) -> dict:
        return {
            'message_type': self.message_type.value,
            'timestamp': self.timestamp,
            'session_id': self.session_id
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())