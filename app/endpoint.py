import json
from http import HTTPStatus
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from starlette.responses import Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from datetime import datetime, timedelta, timezone

router = APIRouter()

SECRET_KEY = "0e65a292cb8210f64486d22690b559cdf5308a6dac155dc5e3a7eca82007290c"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "hashed_password": "$2b$12$ZKYjXFA0FoIKKa1TrlnKdeiUpm1QAZrYSIzWbkGl5hSilI0SJEzue",
    },
}


class Token(BaseModel):
    access_token: str


class TokenData(BaseModel):
    username: str | None = None


class UserSchema(BaseModel):
    """User Schema"""

    username: str
    full_name: str


class UserInDB(UserSchema):
    hashed_password: str


# Create password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Create security scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

# compare plain with hashed password


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# hash the plain password
def get_password_hash(password):
    return pwd_context.hash(password)


# get user out of fake with the username as key
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


# authenticate the user by checking if user exists in fake db and if the password is correct
def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)

    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False

    return user


# creating the access token, by giving the data that has to be encrypted and the expiration date of the token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


# return the user from access token, checking if token is correct and if user with correct username exists
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = lambda message: HTTPException(
        status_code=HTTPStatus.UNAUTHORIZED,
        detail=message,
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except ExpiredSignatureError:
        raise credentials_exception(message="The credentials has expired!")
    except InvalidTokenError:
        raise credentials_exception(message="Could not validate credentials!")
    user = get_user(fake_users_db, username=token_data.username)

    if user is None:
        raise credentials_exception(message="Could not validate credentials!")
    return user


@router.post("/login", dependencies=[])
async def handle_login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Response:
    user = authenticate_user(
        fake_users_db, username=form_data.username, password=form_data.password
    )

    if not user:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(seconds=20)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return Token(access_token=access_token, token_type="bearer")


@router.get("/me", dependencies=[])
async def read_users_me(current_user: Annotated[UserSchema, Depends(get_current_user)]):
    print("The request has been successful!")
    return current_user
