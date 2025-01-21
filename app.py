from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import RedirectResponse

from pydantic import BaseModel
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from llama_index.core import GPTVectorStoreIndex, StorageContext, load_index_from_storage, Document
from pytube import YouTube
from PyPDF2 import PdfReader
import requests
import openai
import asyncio
import os
import re

import boto3
from botocore.exceptions import NoCredentialsError
from botocore.exceptions import ClientError

import sys

from dotenv import load_dotenv
import os

load_dotenv()


# Set OpenAI API Key
openai.api_key = os.getenv("OPENAI_API_KEY")

app = FastAPI()

#temporary storage for documents
documents = []

#global link
current_loaded_index = None

async def some_function_to_load_index(new_index):
    global current_loaded_index
    current_loaded_index = new_index

#AWS persist
AWS_ACCESS_KEY = os.getenv("ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("SECRET_ACCESS_KEY")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
S3_FOLDER = os.getenv("S3_FOLDER")
REGION = os.getenv("REGION")

#aws connection
s3_client = boto3.client(
    "s3",
    aws_access_key_id = AWS_ACCESS_KEY,
    aws_secret_access_key = AWS_SECRET_KEY,
    region_name = REGION
)

def get_known_website_indexes():
    try:
        response = s3_client.list_objects_v2(Bucket = S3_BUCKET_NAME, Prefix = S3_FOLDER)
        if "Contents" in response:
            return [
                obj["Key"].replace(S3_FOLDER, "").replace("index_", "").replace(".json", "")
                for obj in response["Contents"]
            ]
        return []
    except Exception as e:
        print(f"Error listed S3 Buckets contents: {e}")
        return []

def upload_to_s3(file_path):
    try:
        file_name = os.path.basename(file_path)
        s3_client.upload_file(
            file_path,
            S3_BUCKET_NAME,
            f"{S3_FOLDER}{file_name}"
        )
        print(f"Successfully uploaded {file_name} to {S3_BUCKET_NAME}/{S3_FOLDER}")
        return True
    except NoCredentialsError:
        print("AWS credentials not available.")
        return False
    except Exception as e:
        print(f"Error uploading to S3: {e}")
        return False

#Function to extract text content from HTML
def extract_text(soup):
  for element in soup(["script", "style", "header", "footer", "nav"]):
    element.decompose() #Removes element from DOM

  text = soup.get_text(separator = "", strip=True)

  text = re.sub(r"\s+", " ", text)
  return text

def get_internal_links(base_url, soup):
  #for link in soup.find_all("a", href=True):
    #print(f"[DEBUG] Found link: {link['href']}")

  internal_links = set()
  for a_tag in soup.find_all("a", href = True):
    href = a_tag["href"]
    # Skip JavaScript and anchor links
    if "javascript:void" in href or "#" in href:
        continue
    #print(href)


    #Convert relative links to absolute
    link = urljoin(base_url, href)


    #Include internal links (same domain)
    if base_url in link:
      internal_links.add(link)
  return list(internal_links)

#recursive scraping
def scrape_recursive(base_url, soup, max_depth=1, current_depth=0, visited=None):
    if visited is None:
        visited = set()

    if current_depth > max_depth:
        return

    content = extract_text(soup)
    print(f"[DEBUG] Extracted {len(content)} characters from {base_url} (depth {current_depth})")
    if len(content.strip()) == 0:
        print(f"[DEBUG] No readable content on {base_url}")
    else:
        cleaned_content = clean_text(content)
        #print(cleaned_content)
        chunks = list(split_text(cleaned_content, max_length=1000))
        for chunk in chunks:
            documents.append(Document(text=chunk))

    internal_links = get_internal_links(base_url, soup)
    print(f"[DEBUG] Found {len(internal_links)} internal links on {base_url}")

    for link in internal_links:
        if link in visited:
            continue
        visited.add(link)
        try:
            sub_response = requests.get(link, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            sub_response.raise_for_status()
            sub_soup = BeautifulSoup(sub_response.content, "html.parser")
            scrape_recursive(base_url, sub_soup, max_depth, current_depth + 1, visited)
        except Exception as e:
            print(f"[DEBUG] Failed to scrape {link}: {e}")
            continue


def clean_text(text):
    # Add space between words where needed (e.g., "IntentData" -> "Intent Data")
    text = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', text)
    # Replace any multiple spaces with a single space
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def split_text(text, max_length=1000):
    words = text.split()
    for i in range(0, len(words), max_length):
        yield " ".join(words[i:i + max_length])


def create_batches(documents, batch_size=50):
    for i in range(0, len(documents), batch_size):
        yield documents[i:i + batch_size]

#add a redirect 
@app.get("/")
async def docs_redirect():
  return RedirectResponse(url = "/docs")

@app.post("/upload")
async def upload_file(file: UploadFile):
    file_path = f"temp/{file.filename}"
    os.makedirs("temp", exist_ok=True)

    with open(file_path, "wb") as f:
        f.write(await file.read())

    if file.filename.endswith(".pdf"):
        reader = PdfReader(file_path)
        all_text = ""
        
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:  # Check if text is not None
                all_text += page_text + "\n"

        # Split PDF text into smaller chunks
        chunks = list(split_text(all_text, max_length=1000))
        documents = [Document(text=chunk) for chunk in chunks]

        # Create and persist batches
        batches = list(create_batches(documents, batch_size=50))
        for batch in batches:
            index = GPTVectorStoreIndex.from_documents(batch)
            index.storage_context.persist(persist_dir = "pdf_index_storage")

        return {"message": f"PDF processed and indexed with {len(documents)} chunks!"}

    return {"message": "Unsupported file format"}

#class YoutubeURL(BaseModel):
#  url:str

#@app.post("/youtube")
#async def process_youtube(video: YoutubeURL):
#  yt = YouTube(video.url)
#  captions = yt.captions.get_by_language_code("en")
#  if captions:
#    transcript = captions.generate_srt_captions()
#    documents.append(Document(text = transcript))
#    return {"message": "Youtube captions processed successfully"}
#  return {"message": "No captions available for this video."}

class QueryInput(BaseModel):
  query:str

@app.post("/query")
async def query_index(query: QueryInput):
  #if not documents:
    #return {"message": "No documents indexed yet!"}

  #storage_context = StorageContext.from_defaults(persist_dir = "storage")
  #index = load_index_from_storage(storage_context)
    index = current_loaded_index

    if current_loaded_index is None:
        return {"error": "No index is currently loaded."}

    query_engine = index.as_query_engine()

    # Perform the query
    response = query_engine.query(query.query)
  
    return {"response": str(response)}

class URLInput(BaseModel):
  url:str

@app.post("/scrape")
async def scrape_website(url_input: URLInput):
    url = url_input.url
    print(url)

    url_identifier = url.replace("https://", "").replace("http://", "").replace("/", "_")
    print(url_identifier)

    s3_path = f"{S3_FOLDER}{url_identifier}/"
    print(s3_path)

    #checking if the index already exists in S3
    try:
        s3_client.head_object(Bucket=S3_BUCKET_NAME, Key=s3_path+"default__vector_store.json")
        print(f"File '{s3_path}' exists in '{S3_BUCKET_NAME}'!")

        local_storage_path = "storage"
        os.makedirs(local_storage_path, exist_ok=True)

        for file_name in ["default__vector_store.json", "docstore.json", "graph_store.json", "index_store.json"]:
            s3_client.download_file(S3_BUCKET_NAME, s3_path + file_name, os.path.join(local_storage_path, file_name))
            print(f"Downloaded {file_name} from S3")

        storage_context = StorageContext.from_defaults(persist_dir=local_storage_path)
        global current_loaded_index
        current_loaded_index = load_index_from_storage(storage_context)
        return {"message": "Index loaded successfully from S3 and ready for querying!"}
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            print(f"File '{s3_path}' does NOT exist in '{S3_BUCKET_NAME}'.")
        else:
            raise e  # Unexpected error

    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Failed to scrape website: {e}")

    soup = BeautifulSoup(response.content, "html.parser")
    #print(soup)
    
    # Start recursive scraping from the main page
    visited = set()  # Keep track of visited links
    scrape_recursive(url, soup, max_depth=1, visited=visited)  # change max_depth changes how far it scrapes to search
    full_index = GPTVectorStoreIndex.from_documents(documents)
    full_index.storage_context.persist(persist_dir="storage")
    
    # Upload to S3
    for filename in os.listdir("storage"):
        file_path = os.path.join("storage", filename)
        s3_client.upload_file(file_path, S3_BUCKET_NAME, s3_path+filename)
        print(f"Uploaded {filename}")
    print("message: Persisted new link to S3")
    
    return {"message": f"Successfully scraped {len(visited)} unique pages!"}

#async def test_scraper():
#    result = await scrape_website(URLInput(url="https://www.bilintechnology.com/"))
#    print(result)

#asyncio.run(test_scraper())

#if __name__ == "__main__":
#    import uvicorn
#    uvicorn.run(app, host="127.0.0.1", port=8000)