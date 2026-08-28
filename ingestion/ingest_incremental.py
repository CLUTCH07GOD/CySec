"""
Incremental Standards Ingestion
----------------------------------
Wrapper around ingest_standards.py that skips documents already present
in the ChromaDB collection. Only new or changed documents are processed.

Usage:
    python ingest_incremental.py              # incremental (skip existing)
    python ingest_incremental.py --force      # re-ingest everything
    python ingest_incremental.py --dry-run    # show what would be ingested

This module reuses all functions from ingest_standards.py (discover_documents,
extract_text, chunk_text) without modifying them.
"""

import os
import sys

# Ensure project root is importable
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import argparse
import chromadb
from sentence_transformers import SentenceTransformer

import ingest_standards


def get_ingested_sources(collection) -> set[str]:
    """
    Queries the ChromaDB collection metadata to find all source_file values
    that have already been ingested.

    Returns a set of (jurisdiction, framework, source_file) tuples.
    """
    try:
        all_meta = collection.get(include=["metadatas"])["metadatas"]
    except Exception:
        return set()

    ingested = set()
    for m in all_meta:
        key = (
            m.get("jurisdiction", ""),
            m.get("framework", ""),
            m.get("source_file", ""),
        )
        ingested.add(key)
    return ingested


def run_incremental(force: bool = False, dry_run: bool = False):
    """
    Ingests only new documents into ChromaDB.

    Args:
        force: If True, re-ingest all documents regardless of existing state.
        dry_run: If True, just print what would be ingested without doing it.
    """
    docs = ingest_standards.discover_documents(ingest_standards.STANDARDS_DIR)
    if not docs:
        print(
            f"No documents found under '{ingest_standards.STANDARDS_DIR}/'. "
            f"Expected structure: {ingest_standards.STANDARDS_DIR}/<jurisdiction>/<framework>/*.pdf"
        )
        return

    print(f"Discovered {len(docs)} document(s) total.")

    client = chromadb.PersistentClient(path=ingest_standards.CHROMA_DB_DIR)
    collection = client.get_or_create_collection(ingest_standards.COLLECTION_NAME)

    if force:
        print("--force flag set: re-ingesting ALL documents.\n")
        to_ingest = docs
    else:
        ingested = get_ingested_sources(collection)
        print(f"Already ingested: {len(ingested)} unique source files.\n")

        to_ingest = []
        for doc in docs:
            source_name = os.path.basename(doc["path"])
            key = (doc["jurisdiction"], doc["framework"], source_name)
            if key in ingested:
                print(f"  [SKIP] {doc['jurisdiction']}/{doc['framework']}/{source_name} (already ingested)")
            else:
                print(f"  [NEW]  {doc['jurisdiction']}/{doc['framework']}/{source_name}")
                to_ingest.append(doc)

    if not to_ingest:
        print("\nNothing new to ingest. All documents are up-to-date.")
        return

    if dry_run:
        print(f"\n[DRY RUN] Would ingest {len(to_ingest)} new document(s). No changes made.")
        return

    print(f"\nIngesting {len(to_ingest)} new document(s)...\n")
    embedder = SentenceTransformer(ingest_standards.EMBED_MODEL_NAME)

    total_chunks = 0
    for doc in to_ingest:
        text = ingest_standards.extract_text(doc["path"])
        chunks = ingest_standards.chunk_text(
            text, ingest_standards.CHUNK_SIZE_WORDS, ingest_standards.CHUNK_OVERLAP_WORDS
        )
        if not chunks:
            print(f"  WARNING: no extractable text in {doc['path']} (scanned PDF?)")
            continue

        embeddings = embedder.encode(chunks).tolist()
        source_name = os.path.basename(doc["path"])
        ids = [
            f"{doc['jurisdiction']}__{doc['framework']}__{source_name}__{i}"
            for i in range(len(chunks))
        ]
        metadatas = [
            {
                "jurisdiction": doc["jurisdiction"],
                "framework": doc["framework"],
                "source_file": source_name,
                "chunk_index": i,
            }
            for i in range(len(chunks))
        ]

        collection.upsert(
            ids=ids, embeddings=embeddings, documents=chunks, metadatas=metadatas
        )
        total_chunks += len(chunks)
        print(f"  Ingested {len(chunks)} chunks from {doc['path']}")

        # Auto-extract Agent 1 structured controls into structured_controls/<jurisdiction>__<framework>.json
        try:
            import agents.agent1_ingestion as agent1
            agent1.ingest_single_file(doc["path"], doc["jurisdiction"], doc["framework"])
            print(f"  [OK] Structured controls automatically extracted for {doc['jurisdiction']}/{doc['framework']}")
        except Exception as exc:
            print(f"  [NOTE] Structured control auto-extraction note: {exc}")

    # Log to pipeline logger if available
    try:
        import pipeline_logger
        pipeline_logger.log_info(
            "incremental_ingestion",
            f"Ingested {len(to_ingest)} new documents ({total_chunks} chunks total).",
            extra={"documents": len(to_ingest), "chunks": total_chunks},
        )
    except ImportError:
        pass

    print(f"\nDone. {total_chunks} new chunks ingested into '{ingest_standards.CHROMA_DB_DIR}/'.")


def main():
    parser = argparse.ArgumentParser(description="Incremental Standards Ingestion")
    parser.add_argument(
        "--force", action="store_true",
        help="Re-ingest all documents, ignoring what's already in ChromaDB"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be ingested without actually doing it"
    )
    args = parser.parse_args()
    run_incremental(force=args.force, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
