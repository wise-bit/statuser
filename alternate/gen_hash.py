from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os

load_dotenv()

hashed_password = os.getenv("HASHED_PASSWORD")

s = generate_password_hash("status1474!!")
print(check_password_hash(hashed_password, "status1474!!"))
