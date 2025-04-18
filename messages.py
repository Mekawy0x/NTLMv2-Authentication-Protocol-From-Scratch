import json
from enum import Flag, auto
from typing import Dict, Any, Optional
from datetime import datetime
import base64
from message_types import MessageType, BaseMessage

class NTLMFlags(Flag):
    """NTLM Protocol flags simulation"""
    NEGOTIATE_UNICODE = auto()
    NEGOTIATE_OEM = auto()
    REQUEST_TARGET = auto()
    NEGOTIATE_SIGN = auto()
    NEGOTIATE_SEAL = auto()
    NEGOTIATE_NTLM = auto()
    NEGOTIATE_LOCAL_CALL = auto()
    NEGOTIATE_ALWAYS_SIGN = auto()
    TARGET_TYPE_DOMAIN = auto()
    TARGET_TYPE_SERVER = auto()
    TARGET_TYPE_SHARE = auto()
    NEGOTIATE_VERSION = auto()
    NEGOTIATE_128 = auto()
    NEGOTIATE_KEY_EXCH = auto()
    NEGOTIATE_56 = auto()

class NegotiateMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.NEGOTIATE)
        self.hostname = ""
        self.domain = ""

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'hostname': self.hostname,
            'domain': self.domain
        })
        return data

class ChallengeMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.CHALLENGE)
        self.challenge = b''
        self.target_name = ""

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'challenge': base64.b64encode(self.challenge).decode('utf-8'),
            'target_name': self.target_name
        })
        return data

class AuthenticateMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.AUTHENTICATE)
        self.username = ""
        self.password = ""

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'username': self.username,
            'password': self.password
        })
        return data