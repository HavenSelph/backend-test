from typing import Annotated
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import Relationship
from jose import jwt
from argon2 import PasswordHasher
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from config import SECRET_KEY, ALGORITHM, TOKEN_URL
from sqlalchemy.orm import Session
from crud import get_account_from_username
from database import get_db, Base

ph = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL)


class BadCredentials(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


class DisabledAccount(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail="This account is disabled.")
        
        
class PermissionDenied(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this resource.")


def create_access_token(username: str):
    return jwt.encode({"sub": username}, key=SECRET_KEY, algorithm=ALGORITHM)


def validate_token(token: str = Depends(oauth2_scheme)):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.JWTError:
        return False
    

def verify_password(hashed_password: str, password: str):
    return ph.verify(hashed_password, password)


async def get_current_account(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    token = validate_token(token)
    if not token:
        raise BadCredentials()
    account = get_account_from_username(db, token.get("sub"))
    if not account:
        raise BadCredentials()
    if account.disabled:
        raise DisabledAccount()
    return account


def authenticate_account(username: str, password: str, db: Session):
    account = get_account_from_username(db, username)
    if not account:
        raise BadCredentials()
    if not verify_password(account.password, password): 
        raise BadCredentials()
    if account.disabled:
        raise DisabledAccount()
    return account


class Account(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String, nullable=False)
    disabled = Column(Boolean, default=False)

    permissions = Relationship("Permission", secondary="account_permission", back_populates="accounts")
    roles = Relationship("Role", secondary="account_role", back_populates="accounts")


class Permission(Base):
    __tablename__ = "permission"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String, nullable=False)
    accounts = Relationship("Account", secondary="account_permission", back_populates="permissions")
    roles = Relationship("Role", secondary="role_permission", back_populates="permissions")


class AccountPermission(Base):
    __tablename__ = "account_permission"
    id = Column(Integer, primary_key=True)
    account_id = ForeignKey('user.id')
    permission_id = ForeignKey('permission.id')


class Role(Base):
    __tablename__ = "role"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String, nullable=False)
    permissions = Relationship("Permission", secondary="role_permission", back_populates="roles")
    accounts = Relationship("Account", secondary="account_role", back_populates="roles")


class RolePermission(Base):
    __tablename__ = "role_permission"
    id = Column(Integer, primary_key=True)
    role_id = ForeignKey('role.id')
    permission_id = ForeignKey('permission.id')


class AccountRole(Base):
    __tablename__ = "account_role"
    id = Column(Integer, primary_key=True)
    account_id = ForeignKey('user.id')
    role_id = ForeignKey('role.id')


class PermissionManager:
    pass


class PermissionsValidator:
    def __init__(self, permissions: list[str]):
        self.permissions = permissions
        
    def __call__(self, user: Annotated[Account, Depends(get_current_account)]):
        # TODO: Here we can get whatever permissions the user has and compare them...
        # with the permissions required for the endpoint.
        permission_granted = False
        if not permission_granted:
            raise PermissionDenied()
        return True
