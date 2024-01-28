from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class Message(BaseModel):
    message: str


class AccountBase(BaseModel):
    username: str
    

class AccountCreate(AccountBase):
    password: str
    

class Account(AccountBase):
    id: int
    disabled: bool
