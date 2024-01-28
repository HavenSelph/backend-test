from dotenv import load_dotenv
from os import getenv


load_dotenv()
SECRET_KEY = getenv("SECRET_KEY")
ALGORITHM = "HS256"
CLIENT_ORIGIN = "http://localhost"
PORT = 8000
TOKEN_URL = "/token"
