"""
Neo4j Graph & Vector Utilities
--------------------------------
Handles connection, vector indexing, and hybrid Cypher graph retrieval
for Neo4j. If Neo4j credentials are not set or the database server is offline,
calls to `is_neo4j_available()` return False and rag_utils seamlessly falls
back to ChromaDB.

Config (via environment variables or defaults):
    NEO4J_URI      : e.g. "bolt://localhost:7687" or "neo4j+s://xxxx.databases.neo4j.io"
    NEO4J_USERNAME : e.g. "neo4j"
    NEO4J_PASSWORD : e.g. "password"
"""

import os
import logging
from typing import Optional, List, Dict, Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

# Config defaults (reads from .env if present)
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

VECTOR_INDEX_NAME = "standards_vector_index"
VECTOR_DIMENSION = 384  # Matches all-MiniLM-L6-v2 embedding dimension

_driver = None
_available: Optional[bool] = None
_force_disabled: bool = False


def get_driver():
    """Returns a Neo4j Bolt driver instance if available."""
    global _driver, _available
    if _driver is not None and _available is True:
        return _driver

    try:
        from neo4j import GraphDatabase
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        # Verify connectivity
        _driver.verify_connectivity()
        _available = True
        logger.info(f"Connected successfully to Neo4j at {NEO4J_URI}")
    except Exception as exc:
        _driver = None
        _available = False
        logger.info(f"Neo4j connection unavailable ({exc}). Using ChromaDB vector fallback.")

    return _driver


def close_driver():
    """Closes the Neo4j driver connection."""
    global _driver, _available
    if _driver:
        try:
            _driver.close()
        except Exception:
            pass
        _driver = None
        _available = None


def is_neo4j_available() -> bool:
    """Returns True if Neo4j driver can connect successfully and isn't force-disabled."""
    global _available, _force_disabled
    if _force_disabled:
        return False
    if _available is not None:
        return _available
    get_driver()
    return _available if _available is not None else False


def force_disable(disable: bool = True):
    """Force disable or enable Neo4j retrieval for fallback testing."""
    global _force_disabled
    _force_disabled = disable


def reconnect(uri: str, user: str, password: str) -> bool:
    """Updates Neo4j connection parameters and attempts reconnection."""
    global NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, _driver, _available, _force_disabled
    _force_disabled = False
    close_driver()
    NEO4J_URI = uri
    NEO4J_USER = user
    NEO4J_PASSWORD = password
    return is_neo4j_available()


def setup_vector_index():
    """
    Creates the vector index in Neo4j if it does not already exist.
    Uses native vector index syntax for Neo4j 5+.
    """
    driver = get_driver()
    if not driver:
        return False

    cypher_create_index = f"""
    CREATE VECTOR INDEX {VECTOR_INDEX_NAME} IF NOT EXISTS
    FOR (c:Chunk) ON (c.embedding)
    OPTIONS {{
        indexConfig: {{
            `vector.dimensions`: {VECTOR_DIMENSION},
            `vector.similarity_function`: 'cosine'
        }}
    }}
    """
    try:
        with driver.session() as session:
            session.run(cypher_create_index)
        logger.info(f"Neo4j vector index '{VECTOR_INDEX_NAME}' initialized.")
        return True
    except Exception as exc:
        logger.warning(f"Error setting up Neo4j vector index: {exc}")
        return False


def retrieve_neo4j(
    query_embedding: List[float],
    k: int = 5,
    jurisdictions: Optional[List[str]] = None,
    frameworks: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieves top-k relevant document chunks from Neo4j using Vector Search
    combined with Graph property filtering.

    Returns:
        List of dicts: [{text, jurisdiction, framework, source_file, score}]
    """
    driver = get_driver()
    if not driver:
        return []

    cypher = f"""
    CALL db.index.vector.queryNodes('{VECTOR_INDEX_NAME}', $k * 2, $embedding)
    YIELD node, score
    WHERE ($jurisdictions IS NULL OR toLower(node.jurisdiction) IN $jurisdictions)
      AND ($frameworks IS NULL OR toLower(node.framework) IN $frameworks)
    RETURN node.text AS text,
           node.jurisdiction AS jurisdiction,
           node.framework AS framework,
           node.source_file AS source_file,
           score
    LIMIT $k
    """

    norm_jurisdictions = [j.lower() for j in jurisdictions] if jurisdictions else None
    norm_frameworks = [f.lower() for f in frameworks] if frameworks else None

    params = {
        "embedding": query_embedding,
        "k": k,
        "jurisdictions": norm_jurisdictions,
        "frameworks": norm_frameworks,
    }

    try:
        hits = []
        with driver.session() as session:
            result = session.run(cypher, params)
            for record in result:
                hits.append({
                    "text": record["text"],
                    "jurisdiction": record["jurisdiction"],
                    "framework": record["framework"],
                    "source_file": record["source_file"],
                    "score": float(record["score"]),
                })
        return hits
    except Exception as exc:
        logger.warning(f"Neo4j retrieval error: {exc}")
        return []


if __name__ == "__main__":
    print(f"Neo4j Configured URI: {NEO4J_URI}")
    print(f"Neo4j Available: {is_neo4j_available()}")
