from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from llama_index.core import GPTVectorStoreIndex, StorageContext, load_index_from_storage, Document
import requests
import openai
import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import re
import asyncio

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# AWS and MongoDB Configurations
def get_secret(secret_name):
    client = boto3.client("secretsmanager", region_name="your-region")
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response["SecretString"]
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None

ACCESS_KEY_ID = get_secret("ACCESS_KEY_ID")
SECRET_ACCESS_KEY = get_secret("SECRET_ACCESS_KEY")
OPENAI_API_KEY = get_secret("OPENAI_API_KEY")
S3_BUCKET_NAME = get_secret("S3_BUCKET_NAME")
S3_FOLDER = get_secret("S3_FOLDER")
REGION = get_secret("REGION")
MONGODB_URI = get_secret("MONGODB_URI")
SECRET_KEY = get_secret("SECRET_KEY")
ALGORITHM = get_secret("ALGORITHM")

# OpenAI API Key
openai.api_key = os.getenv("OPENAI_API_KEY")

# MongoDB Client
def get_mongo_client():
    return MongoClient(MONGODB_URI)

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# AWS S3 Client
s3_client = boto3.client(
    "s3",
    aws_access_key_id=ACCESS_KEY_ID,
    aws_secret_access_key=SECRET_ACCESS_KEY,
    region_name=REGION,
)

# FastAPI Instance
app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://main.d3iovjyuh6mk6f.amplifyapp.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Temporary storage
documents = []
current_loaded_index = None


# --- Utility Functions ---
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_internal_links(base_url, soup):
    internal_links = set()
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if "javascript:void" in href or "#" in href:
            continue
        link = urljoin(base_url, href)
        if base_url in link:
            internal_links.add(link)
    return list(internal_links)

def clean_text(text):
    text = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def split_text(text, max_length=1000):
    words = text.split()
    for i in range(0, len(words), max_length):
        yield " ".join(words[i:i + max_length])

def scrape_recursive(base_url, soup, max_depth=1, current_depth=0, visited=None):
    if visited is None:
        visited = set()
    if current_depth > max_depth:
        return
    content = clean_text(soup.get_text(separator="", strip=True))
    chunks = list(split_text(content, max_length=1000))
    for chunk in chunks:
        documents.append(Document(text=chunk))
    internal_links = get_internal_links(base_url, soup)
    for link in internal_links:
        if link in visited:
            continue
        visited.add(link)
        try:
            sub_response = requests.get(link, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            sub_response.raise_for_status()
            sub_soup = BeautifulSoup(sub_response.content, "html.parser")
            scrape_recursive(base_url, sub_soup, max_depth, current_depth + 1, visited)
        except Exception:
            continue


# --- Authentication Routes ---
class User(BaseModel):
    email: str
    password: str

@app.get("/test-db")
async def test_db():
    client = get_mongo_client()
    db = client["userdb"]
    users_collection = db["credentials"]
    user = users_collection.find_one({"email": "test@example.com"})
    client.close()
    return {"User Found:": str(user)}


@app.post("/api/register")
async def register(user: User):
    client = get_mongo_client()
    db = client["userdb"]
    users_collection = db["credentials"]
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    users_collection.insert_one({"email": user.email, "password": hashed_password})
    client.close()
    return {"message": "User registered successfully"}

@app.post("/register")
async def register(user: User):
    client = get_mongo_client()
    db = client["userdb"]
    users_collection = db["credentials"]
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    users_collection.insert_one({"email": user.email, "password": hashed_password})
    client.close()
    return {"message": "User registered successfully"}

@app.post("/login")
async def login(user: User):
    client = get_mongo_client()
    db = client["userdb"]
    users_collection = db["credentials"]
    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=60))
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/test")
async def test():
    return {"test": "test"}

@app.post("login")
async def login(user: User):
    client = get_mongo_client()
    db = client["userdb"]
    users_collection = db["credentials"]
    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=60))
    client.close()
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/me")
async def read_user_data(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"email": email}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# --- Scraping Routes ---
class URLInput(BaseModel):
    url: str

@app.post("/api/scrape")
async def scrape_website(url_input: URLInput):
    global current_loaded_index
    url_identifier = url_input.url.replace("https://", "").replace("http://", "").replace("/", "_")
    s3_path = f"{S3_FOLDER}{url_identifier}/"
    try:
        s3_client.head_object(Bucket=S3_BUCKET_NAME, Key=s3_path + "default__vector_store.json")
        local_storage_path = "storage"
        os.makedirs(local_storage_path, exist_ok=True)
        for file_name in ["default__vector_store.json", "docstore.json", "graph_store.json", "index_store.json"]:
            s3_client.download_file(S3_BUCKET_NAME, s3_path + file_name, os.path.join(local_storage_path, file_name))
        storage_context = StorageContext.from_defaults(persist_dir=local_storage_path)
        current_loaded_index = load_index_from_storage(storage_context)
        return {"message": "Index loaded successfully from S3!"}
    except ClientError:
        pass
    response = requests.get(url_input.url, headers={"User-Agent": "Mozilla/5.0"})
    soup = BeautifulSoup(response.content, "html.parser")
    scrape_recursive(url_input.url, soup, max_depth=1)
    full_index = GPTVectorStoreIndex.from_documents(documents)
    full_index.storage_context.persist(persist_dir="storage")
    for filename in os.listdir("storage"):
        s3_client.upload_file(os.path.join("storage", filename), S3_BUCKET_NAME, s3_path + filename)
    current_loaded_index = full_index
    return {"message": "Website scraped and index created!"}

class QueryInput(BaseModel):
  query:str
@app.post("/api/query")
async def query_index(query: QueryInput):
    if current_loaded_index is None:
        return {"error": "No index is currently loaded."}
    query_engine = current_loaded_index.as_query_engine()
    response = query_engine.query(query.query)
    return {"response": str(response)}

# Redirect to docs by default
@app.get("/api/")
async def docs_redirect():
    return RedirectResponse(url="/docs")