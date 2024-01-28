import secure
from typing import Annotated
from sqlalchemy.orm import Session
from fastapi import FastAPI, Depends
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from config import CLIENT_ORIGIN
from database import engine, get_db, Base
import auth
import crud
import schemas

Base.metadata.create_all(bind=engine)
app = FastAPI()
hsts = secure.StrictTransportSecurity().max_age(31536000).include_subdomains()
referrer = secure.ReferrerPolicy().no_referrer()
cache_value = secure.CacheControl().no_cache().no_store().max_age(0).must_revalidate()
x_frame_options = secure.XFrameOptions().deny()

secure_headers = secure.Secure(
    hsts=hsts,
    referrer=referrer,
    cache=cache_value,
    xfo=x_frame_options
)


@app.middleware("http")
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=[CLIENT_ORIGIN],
    allow_headers=["Authorization", "Content-Type"],
    max_age=86400,
)


@app.get("/", include_in_schema=False)
async def documentation_redirect():
    return RedirectResponse(url="/docs")


@app.post("/token/", response_model=schemas.Token)
async def get_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
    # Auth will raise an exception in the case the user should not be authenticated.
    account = auth.authenticate_account(form_data.username, form_data.password, db)
    return {"access_token": auth.create_access_token(account.username), "token_type": "bearer"}


@app.post("/accounts/")
async def create_user(account: schemas.AccountCreate, db: Session = Depends(get_db)):
    db_account = crud.get_account_from_username(db, username=account.username)
    if db_account:
        return {"error": "Username already registered."}
    return crud.create_account(db=db, username=account.username, password=auth.ph.hash(account.password))


@app.get("/accounts/")
async def get_accounts(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_accounts(db, skip=skip, limit=limit)


@app.get("/accounts/{account_id}")
async def get_account(account_id: int, db: Session = Depends(get_db)):
    return crud.get_account_from_id(db, account_id=account_id)


@app.delete("/accounts/{account_id}")
async def delete_account(account_id: int, db: Session = Depends(get_db)):
    return crud.delete_account(db, account_id=account_id)


@app.get("/accounts/me/", response_model=schemas.Account)
async def get_my_account(account: Annotated[auth.Account, Depends(auth.get_current_account)]):
    return account


@app.get("/message/", response_model=schemas.Message, dependencies=[Depends(auth.PermissionsValidator(["read:message"]))])
async def hidden_message():
    return {"message": "Hello World!"}
