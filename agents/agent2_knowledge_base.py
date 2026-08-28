"""
Agent 2 — Knowledge Base Agent
--------------------------------
Loads the structured controls produced by Agent 1 (structured_controls/*.json)
and embeds them into a ChromaDB collection, one vector per control.

Duplicate control IDs are handled automatically by appending
__dup2, __dup3, ... to duplicate Chroma IDs.

Run with:
    python agents/agent2_knowledge_base.py
"""

import os
import json
import glob
import torch
from collections import Counter
import chromadb
try:
    import agents.config as config
except ImportError:
    import config

COLLECTION_NAME = "controls"


def load_all_controls() -> list[dict]:
    controls = []

    for path in sorted(glob.glob(f"{config.STRUCTURED_CONTROLS_DIR}/*.json")):
        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    controls.extend(data)
                elif isinstance(data, dict):
                    if "controls" in data and isinstance(data["controls"], list):
                        # Ensure jurisdiction and framework metadata are set from the filename if missing
                        fn = os.path.basename(path).replace(".json", "")
                        parts = fn.split("__")
                        jurisdiction = parts[0] if len(parts) > 0 else "unknown"
                        framework = parts[1] if len(parts) > 1 else "unknown"
                        for c in data["controls"]:
                            if "jurisdiction" not in c:
                                c["jurisdiction"] = jurisdiction
                            if "framework" not in c:
                                c["framework"] = framework
                        controls.extend(data["controls"])
                    else:
                        print(f"Skipping {path}: expected a list or controls key in dict.")
            except Exception as e:
                print(f"Error loading {path}: {e}")

    return controls


def generate_unique_ids(controls):
    """
    Generate Chroma-safe unique IDs.

    Original IDs:
        eu__gdpr__12

    Duplicate IDs become:
        eu__gdpr__12__dup2
        eu__gdpr__12__dup3
    """

    base_ids = []

    for c in controls:
        base_id = (
            f"{c.get('jurisdiction','unknown')}__"
            f"{c.get('framework','unknown')}__"
            f"{c.get('control_id')}"
        )
        base_ids.append(base_id)

    counter = Counter()
    unique_ids = []

    for base in base_ids:
        counter[base] += 1

        if counter[base] == 1:
            unique_ids.append(base)
        else:
            unique_ids.append(f"{base}__dup{counter[base]}")

    duplicates = sum(v - 1 for v in counter.values() if v > 1)

    if duplicates:
        print(f"Detected {duplicates} duplicate IDs.")
        print("Automatically renamed duplicate Chroma IDs.")

    return unique_ids


def load_all_mappings(ingested_controls: list[dict] = None) -> list[dict]:
    valid_frameworks = set()
    if ingested_controls:
        for c in ingested_controls:
            fw = c.get("framework")
            if fw:
                valid_frameworks.add(str(fw).lower().strip())

    mappings = []
    skipped_count = 0
    for path in sorted(glob.glob(f"{config.MAPPINGS_DIR}/*.json")):
        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    source_file = os.path.basename(path)
                    for item in data:
                        src_fw = str(item.get("source_control", {}).get("framework", "")).lower().strip()
                        tgt_fw = str(item.get("target_control", {}).get("framework", "")).lower().strip()

                        if valid_frameworks:
                            if src_fw not in valid_frameworks or tgt_fw not in valid_frameworks:
                                skipped_count += 1
                                continue

                        item["source_mapping_file"] = source_file
                        mappings.append(item)
            except Exception as e:
                print(f"Error loading mapping {path}: {e}")

    if skipped_count:
        print(f"Filtered out {skipped_count} mappings referencing frameworks not present in structured_controls.")
    return mappings


def safe_encode(embedder, texts: list[str], batch_size: int = 16) -> list:
    """Encodes texts using Qwen2.5 with CUDA memory safety and CPU fallback if needed."""
    from sentence_transformers import SentenceTransformer
    try:
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        embeddings = embedder.encode(texts, batch_size=batch_size, show_progress_bar=True)
        return embeddings.tolist()
    except torch.OutOfMemoryError:
        print("⚠️ CUDA OOM encountered during Qwen2.5 encoding. Retrying with CPU...")
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        embedder_cpu = SentenceTransformer(config.EMBED_MODEL_NAME, device="cpu")
        embeddings = embedder_cpu.encode(texts, batch_size=32, show_progress_bar=True)
        return embeddings.tolist()


def build_chroma_collection(controls, reset_collection: bool = False):
    embedder = config.get_embedder()
    client = chromadb.PersistentClient(path=config.CHROMA_DB_DIR)

    if reset_collection:
        try:
            client.delete_collection(COLLECTION_NAME)
            print(f"Deleted old '{COLLECTION_NAME}' collection to purge legacy embeddings.")
        except Exception:
            pass

    collection = client.get_or_create_collection(COLLECTION_NAME, embedding_function=None)

    if not controls:
        print("No controls found. Run Agent 1 first.")
        return collection

    texts = [
        f"{c.get('title','')}. {c.get('description','')}"
        for c in controls
    ]

    ids = generate_unique_ids(controls)

    metadatas = [
        {
            "control_id": c.get("control_id") or "",
            "title": c.get("title") or "",
            "jurisdiction": c.get("jurisdiction") or "",
            "framework": c.get("framework") or "",
            "source_file": c.get("source_file") or "",
        }
        for c in controls
    ]

    print(f"Generating Qwen2.5 embeddings and inserting {len(controls)} controls in batches...")
    BATCH_SIZE = 2000
    ENCODE_BATCH_SIZE = 16

    for i in range(0, len(controls), BATCH_SIZE):
        end_idx = min(i + BATCH_SIZE, len(controls))
        batch_texts = texts[i:end_idx]
        batch_ids = ids[i:end_idx]
        batch_metadatas = metadatas[i:end_idx]

        print(f" Processing controls chunk {i//BATCH_SIZE + 1}/{(len(controls) + BATCH_SIZE - 1)//BATCH_SIZE} ({i} to {end_idx})...")
        batch_embeddings = safe_encode(embedder, batch_texts, batch_size=ENCODE_BATCH_SIZE)

        collection.upsert(
            ids=batch_ids,
            embeddings=batch_embeddings,
            documents=batch_texts,
            metadatas=batch_metadatas,
        )

    print(
        f"Successfully upserted {len(controls)} controls "
        f"into collection '{COLLECTION_NAME}'."
    )

    return collection


def build_chroma_mappings_collection(mappings, reset_collection: bool = False):
    embedder = config.get_embedder()
    client = chromadb.PersistentClient(path=config.CHROMA_DB_DIR)

    if reset_collection:
        try:
            client.delete_collection("mappings")
            print("Deleted old 'mappings' collection to purge legacy embeddings.")
        except Exception:
            pass

    collection = client.get_or_create_collection("mappings", embedding_function=None)

    if not mappings:
        print("No mappings found.")
        return collection

    texts = []
    ids = []
    metadatas = []

    for idx, m in enumerate(mappings):
        src = m.get("source_control", {})
        tgt = m.get("target_control", {})
        rel = m.get("relationship", "Overlapping")
        sim = str(m.get("similarity", 0.85))

        txt = (
            f"Source: {src.get('framework','')} {src.get('id','')} - {src.get('title','')}. "
            f"Target: {tgt.get('framework','')} {tgt.get('id','')} - {tgt.get('title','')}. "
            f"Relationship: {rel} (Similarity: {sim})"
        )
        texts.append(txt)
        ids.append(f"map__{idx}")
        metadatas.append({
            "source_framework": src.get("framework", ""),
            "source_id": src.get("id", ""),
            "target_framework": tgt.get("framework", ""),
            "target_id": tgt.get("id", ""),
            "relationship": rel,
            "similarity": float(m.get("similarity", 0.85)),
            "source_file": m.get("source_mapping_file", ""),
        })

    print(f"Generating Qwen2.5 embeddings and inserting {len(mappings)} cross-framework mappings in batches...")
    BATCH_SIZE = 2000
    ENCODE_BATCH_SIZE = 16
    
    for i in range(0, len(mappings), BATCH_SIZE):
        end_idx = min(i + BATCH_SIZE, len(mappings))
        batch_texts = texts[i:end_idx]
        batch_ids = ids[i:end_idx]
        batch_metadatas = metadatas[i:end_idx]
        
        print(f" Processing mappings chunk {i//BATCH_SIZE + 1}/{(len(mappings) + BATCH_SIZE - 1)//BATCH_SIZE} ({i} to {end_idx})...")
        batch_embeddings = safe_encode(embedder, batch_texts, batch_size=ENCODE_BATCH_SIZE)
        
        collection.upsert(
            ids=batch_ids,
            embeddings=batch_embeddings,
            documents=batch_texts,
            metadatas=batch_metadatas,
        )

    print(
        f"Successfully upserted {len(mappings)} cross-framework mappings "
        f"into collection 'mappings'."
    )
    return collection


def try_build_neo4j_graph(controls):
    """
    Optional Neo4j graph creation.
    """

    neo4j_uri = os.environ.get("NEO4J_URI")

    if not neo4j_uri:
        print("NEO4J_URI not set. Skipping Neo4j graph.")
        return

    try:
        from neo4j import GraphDatabase
    except ImportError:
        print("neo4j package not installed. Skipping Neo4j graph.")
        return

    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "")

    driver = GraphDatabase.driver(
        neo4j_uri,
        auth=(user, password),
    )

    with driver.session() as session:

        for c in controls:

            session.run(
                """
                MERGE (ctrl:Control {
                    id:$control_id,
                    jurisdiction:$jurisdiction,
                    framework:$framework
                })

                SET ctrl.title=$title,
                    ctrl.description=$description
                """,
                control_id=c.get("control_id"),
                jurisdiction=c.get("jurisdiction"),
                framework=c.get("framework"),
                title=c.get("title"),
                description=c.get("description"),
            )

    driver.close()

    print(f"Created/updated {len(controls)} Neo4j nodes.")


def main():

    controls = load_all_controls()
    mappings = load_all_mappings(ingested_controls=controls)

    print(
        f"Loaded {len(controls)} structured controls from '{config.STRUCTURED_CONTROLS_DIR}/' "
        f"and {len(mappings)} valid cross-framework mappings from '{config.MAPPINGS_DIR}/'."
    )

    # Step 1: Insert structured controls (preserve existing collections)
    build_chroma_collection(controls, reset_collection=False)

    # Step 2: Insert cross-framework mappings (preserve existing collections)
    build_chroma_mappings_collection(mappings, reset_collection=False)

    try_build_neo4j_graph(controls)


if __name__ == "__main__":
    main()