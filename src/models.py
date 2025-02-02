from dataclasses import dataclass
from datetime import datetime


@dataclass
class User:
    username: str
    email: str
    password: str
    created_at: datetime
    updated_at: datetime
    last_login: datetime
    is_active: bool = False
    activation_token: str | None = None

    def to_Item(self) -> dict:
        """Convert User object to DynamoDB item."""
        return {
            'username': self.username,
            'email': self.email,
            'password': self.password,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_login': self.last_login.isoformat(),
            'is_active': self.is_active,
            'activation_token': self.activation_token
        } 

    @classmethod
    def from_Item(cls, item: dict) -> 'User':
        """Create User object from DynamoDB item."""
        return cls(**item)
