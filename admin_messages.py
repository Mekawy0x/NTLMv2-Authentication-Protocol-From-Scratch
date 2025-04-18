from message_types import MessageType, BaseMessage

class ViewLogsMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.VIEW_LOGS)
        self.page = 1
        self.limit = 10

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'page': self.page,
            'limit': self.limit
        })
        return data

class ViewUsersMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.VIEW_USERS)

class ChangeUsernameMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.CHANGE_USERNAME)
        self.new_username = ""

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'new_username': self.new_username
        })
        return data

class AddUserMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.ADD_USER)
        self.username = ""
        self.password = ""
        self.role = ""

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'username': self.username,
            'password': self.password,
            'role': self.role
        })
        return data

class ChangePasswordMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.CHANGE_PASSWORD)
        self.current_password = ""
        self.new_password = ""

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'current_password': self.current_password,
            'new_password': self.new_password
        })
        return data

class RemoveUserMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.REMOVE_USER)
        self.username = ""

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'username': self.username
        })
        return data

class UpdateUserMessage(BaseMessage):
    def __init__(self):
        super().__init__(MessageType.UPDATE_USER)
        self.username = ""
        self.update_type = ""
        self.new_value = ""

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            'username': self.username,
            'update_type': self.update_type,
            'new_value': self.new_value
        })
        return data