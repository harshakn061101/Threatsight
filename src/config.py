import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY      = os.getenv("GROQ_API_KEY")
LANGCHAIN_API_KEY = os.getenv("LANGCHAIN_API_KEY")

LLM_MODEL = "openai/gpt-oss-120b"
LLM_TEMPERATURE = 0.1

EMBEDDING_MODEL     = "all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384

QDRANT_PATH       = "./data/qdrant_db"
QDRANT_COLLECTION = "threatsight_corpus"

DATA_DIR      = "./data"
RAW_DIR       = "./data/raw"
PROCESSED_DIR = "./data/processed"

TOP_K_DENSE          = 10
TOP_K_SPARSE         = 10
TOP_K_FINAL          = 5
SIMILARITY_THRESHOLD = 0.3

MAX_RETRIES            = 3
FAITHFULNESS_THRESHOLD = 0.85

NVD_API_BASE         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 2000