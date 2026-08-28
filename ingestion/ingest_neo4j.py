"""
Neo4j Ingestion Pipeline
------------------------
Transfers ALL standards, chunks, structured controls, and cross-framework
mappings into Neo4j:

1. Chunks & Standards: `standards/<jurisdiction>/<framework>/*.pdf|*.txt`
2. Structured Controls: `structured_controls/*.json`
3. Mappings: `mappings/*.json`

Run with:
    python ingest_neo4j.py
"""

import os
import sys
import glob
import json
import argparse
from sentence_transformers import SentenceTransformer

# Ensure local imports work
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import ingest_standards
import neo4j_utils

STANDARDS_DIR = "standards"
STRUCTURED_DIR = "structured_controls"
MAPPINGS_DIR = "mappings"
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
CHUNK_SIZE_WORDS = 350
CHUNK_OVERLAP_WORDS = 60


def ingest_to_neo4j(force: bool = False):
    if not neo4j_utils.is_neo4j_available():
        print(
            f"[NOTICE] Neo4j server is not reachable at '{neo4j_utils.NEO4J_URI}'. "
            f"Set NEO4J_URI, NEO4J_USERNAME, and NEO4J_PASSWORD environment variables or start Neo4j."
        )
        return False

    print("[INFO] Initializing Neo4j Vector Index...")
    neo4j_utils.setup_vector_index()

    driver = neo4j_utils.get_driver()

    # -----------------------------------------------------------------------
    # Step 1: Ingest Document Chunks
    # -----------------------------------------------------------------------
    docs = ingest_standards.discover_documents(STANDARDS_DIR)
    if docs:
        print(f"\n[STEP 1] Found {len(docs)} document(s) for chunk ingestion:")
        embedder = SentenceTransformer(EMBED_MODEL_NAME)
        total_chunks = 0

        cypher_chunk = """
        MERGE (j:Jurisdiction {name: $jurisdiction})
        MERGE (f:Framework {name: $framework, jurisdiction: $jurisdiction})
        MERGE (f)-[:IN_JURISDICTION]->(j)
        
        MERGE (c:Chunk {id: $chunk_id})
        SET c.text = $text,
            c.jurisdiction = $jurisdiction,
            c.framework = $framework,
            c.source_file = $source_file,
            c.chunk_index = $chunk_index,
            c.embedding = $embedding
            
        MERGE (c)-[:PART_OF]->(f)
        """

        with driver.session() as session:
            for doc in docs:
                text = ingest_standards.extract_text(doc["path"])
                chunks = ingest_standards.chunk_text(text, CHUNK_SIZE_WORDS, CHUNK_OVERLAP_WORDS)
                if not chunks:
                    continue

                source_name = os.path.basename(doc["path"])
                embeddings = embedder.encode(chunks).tolist()

                for i, (chunk_text_str, emb) in enumerate(zip(chunks, embeddings)):
                    chunk_id = f"{doc['jurisdiction']}__{doc['framework']}__{source_name}__{i}"
                    session.run(
                        cypher_chunk,
                        {
                            "chunk_id": chunk_id,
                            "text": chunk_text_str,
                            "jurisdiction": doc["jurisdiction"],
                            "framework": doc["framework"],
                            "source_file": source_name,
                            "chunk_index": i,
                            "embedding": emb,
                        },
                    )
                total_chunks += len(chunks)
                print(f"  [OK] Ingested {len(chunks)} chunks from {doc['path']}")

    # -----------------------------------------------------------------------
    # Step 2: Ingest Structured Controls
    # -----------------------------------------------------------------------
    control_files = sorted(glob.glob(os.path.join(STRUCTURED_DIR, "*.json")))
    if control_files:
        print(f"\n[STEP 2] Ingesting structured controls from {len(control_files)} file(s)...")
        cypher_control = """
        MERGE (f:Framework {name: $framework, jurisdiction: $jurisdiction})
        MERGE (ctrl:Control {id: $control_id})
        SET ctrl.title = $title,
            ctrl.description = $description,
            ctrl.framework = $framework,
            ctrl.jurisdiction = $jurisdiction
        MERGE (ctrl)-[:BELONGS_TO]->(f)
        """
        total_controls = 0
        with driver.session() as session:
            for cfile in control_files:
                parts = os.path.basename(cfile).replace(".json", "").split("__")
                if len(parts) != 2:
                    continue
                jurisdiction, framework = parts[0], parts[1]
                with open(cfile, encoding="utf-8") as f:
                    controls_list = json.load(f)
                for ctrl in controls_list:
                    ctrl_id = f"{jurisdiction}__{framework}__{ctrl.get('control_id', ctrl.get('id', 'UNKNOWN'))}"
                    session.run(
                        cypher_control,
                        {
                            "control_id": ctrl_id,
                            "title": ctrl.get("title", ""),
                            "description": ctrl.get("description", ctrl.get("text", "")),
                            "framework": framework,
                            "jurisdiction": jurisdiction,
                        },
                    )
                    total_controls += 1
                print(f"  [OK] Ingested {len(controls_list)} controls from {os.path.basename(cfile)}")

    # -----------------------------------------------------------------------
    # Step 3: Ingest Cross-Framework Control Mappings
    # -----------------------------------------------------------------------
    mapping_files = sorted(glob.glob(os.path.join(MAPPINGS_DIR, "*.json")))
    if mapping_files:
        print(f"\n[STEP 3] Ingesting cross-framework control mappings from {len(mapping_files)} file(s)...")
        cypher_mapping = """
        MATCH (c1:Control {id: $src_id})
        MATCH (c2:Control {id: $tgt_id})
        MERGE (c1)-[r:MAPPED_TO {relationship: $relationship}]->(c2)
        SET r.similarity = $similarity
        """
        total_mappings = 0
        with driver.session() as session:
            for mfile in mapping_files:
                with open(mfile, encoding="utf-8") as f:
                    mappings_list = json.load(f)
                for m in mappings_list:
                    src = m.get("source_control", {})
                    tgt = m.get("target_control", {})
                    src_id = f"{src.get('jurisdiction','')}__{src.get('framework','')}__{src.get('id','')}"
                    tgt_id = f"{tgt.get('jurisdiction','')}__{tgt.get('framework','')}__{tgt.get('id','')}"
                    session.run(
                        cypher_mapping,
                        {
                            "src_id": src_id,
                            "tgt_id": tgt_id,
                            "relationship": m.get("relationship", "Related"),
                            "similarity": float(m.get("similarity", 0.0)),
                        },
                    )
                    total_mappings += 1
                print(f"  [OK] Ingested {len(mappings_list)} mappings from {os.path.basename(mfile)}")

    print(f"\n[SUCCESS] All data ingestion into Neo4j completed!")
    return True


def main():
    parser = argparse.ArgumentParser(description="Neo4j Ingestion Pipeline")
    parser.add_argument("--force", action="store_true", help="Force re-ingest all docs")
    args = parser.parse_args()
    ingest_to_neo4j(force=args.force)


if __name__ == "__main__":
    main()
