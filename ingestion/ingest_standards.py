"""
Standards Ingestion Pipeline
----------------------------
Walks a folder structure of:

    standards/<jurisdiction>/<framework>/*.pdf   (or .txt)

e.g.
    standards/nist/csf/nist_csf_2_0.pdf
    standards/eu/gdpr/gdpr_full_text.pdf
    standards/eu/nis2/nis2_directive.pdf
    standards/india/dpdp/dpdp_act_2023.pdf
    standards/india/cert-in/cert_in_directions.pdf

Extracts text, splits it into overlapping chunks, embeds each chunk with
the same sentence-transformer used for routing, and stores everything in
a persistent ChromaDB collection with metadata:

    {jurisdiction, framework, source_file, chunk_index}

This metadata is what lets the RAG retrieval step later filter to just
"GDPR + DPDP Act" for a comparison question, instead of searching
everything blindly.

Run with:
    python ingest_standards.py
"""

import os
import glob

import chromadb
from sentence_transformers import SentenceTransformer
from pypdf import PdfReader

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
STANDARDS_DIR = "standards"          # expects standards/<jurisdiction>/<framework>/*.pdf|*.txt
CHROMA_DB_DIR = "chroma_db"          # persistent vector store location
COLLECTION_NAME = "standards"
EMBED_MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"   # Qwen2.5 1536-dim embedding model
CHUNK_SIZE_WORDS = 350
CHUNK_OVERLAP_WORDS = 60


def extract_text(path: str) -> str:
    if path.lower().endswith(".pdf"):
        reader = PdfReader(path)
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    with open(path, encoding="utf-8") as f:
        return f.read()


def chunk_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    words = text.split()
    if not words:
        return []
    chunks = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunk = " ".join(words[start:end])
        if chunk.strip():
            chunks.append(chunk)
        start += chunk_size - overlap
    return chunks


def discover_documents(standards_dir: str) -> list[dict]:
    """Returns a list of {path, jurisdiction, framework} for every PDF/txt found."""
    docs = []
    for jurisdiction_dir in sorted(glob.glob(f"{standards_dir}/*")):
        if not os.path.isdir(jurisdiction_dir):
            continue
        jurisdiction = os.path.basename(jurisdiction_dir)
        for framework_dir in sorted(glob.glob(f"{jurisdiction_dir}/*")):
            if not os.path.isdir(framework_dir):
                continue
            framework = os.path.basename(framework_dir)
            for path in sorted(glob.glob(f"{framework_dir}/*.pdf") + glob.glob(f"{framework_dir}/*.txt")):
                docs.append({"path": path, "jurisdiction": jurisdiction, "framework": framework})
    return docs


def main():
    docs = discover_documents(STANDARDS_DIR)
    if not docs:
        print(
            f"No documents found under '{STANDARDS_DIR}/'. Expected structure:\n"
            f"  {STANDARDS_DIR}/<jurisdiction>/<framework>/*.pdf\n"
            f"e.g. {STANDARDS_DIR}/eu/gdpr/gdpr_full_text.pdf\n"
        )
        return

    print(f"Found {len(docs)} document(s):")
    for d in docs:
        print(f"  [{d['jurisdiction']}/{d['framework']}] {d['path']}")

    print("\nLoading embedding model…")
    embedder = SentenceTransformer(EMBED_MODEL_NAME)

    client = chromadb.PersistentClient(path=CHROMA_DB_DIR)
    collection = client.get_or_create_collection(COLLECTION_NAME)

    total_chunks = 0
    for doc in docs:
        text = extract_text(doc["path"])
        chunks = chunk_text(text, CHUNK_SIZE_WORDS, CHUNK_OVERLAP_WORDS)
        if not chunks:
            print(f"  WARNING: no extractable text in {doc['path']} (scanned PDF? needs OCR)")
            continue

        embeddings = embedder.encode(chunks).tolist()
        source_name = os.path.basename(doc["path"])
        ids = [f"{doc['jurisdiction']}__{doc['framework']}__{source_name}__{i}" for i in range(len(chunks))]
        metadatas = [
            {
                "jurisdiction": doc["jurisdiction"],
                "framework": doc["framework"],
                "source_file": source_name,
                "chunk_index": i,
            }
            for i in range(len(chunks))
        ]

        collection.upsert(ids=ids, embeddings=embeddings, documents=chunks, metadatas=metadatas)
        total_chunks += len(chunks)
        print(f"  Ingested {len(chunks)} chunks from {doc['path']}")

    print(f"\nDone. {total_chunks} total chunks stored in '{CHROMA_DB_DIR}/' (collection: '{COLLECTION_NAME}').")


if __name__ == "__main__":
    main()
