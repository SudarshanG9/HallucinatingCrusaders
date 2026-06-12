"""
ChromaDB client integration for indexing, embedding, and querying incident reports.
"""

import hashlib
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.api.types import Documents, Embeddings, EmbeddingFunction

from soc_analyst.config import settings

logger = logging.getLogger(__name__)

class HashEmbeddingFunction(EmbeddingFunction):
    """Deterministic, zero-dependency unit-length hashing embedding function.

    Generates 384-dimensional vectors. Useful when sentence-transformers or
    onnxruntime cannot be loaded due to internet/dependency constraints.
    """
    def __call__(self, input: Documents) -> Embeddings:
        embeddings = []
        for text in input:
            # Initialize 384 dimensions
            vector = [0.0] * 384
            words = text.lower().split()
            if not words:
                words = ["empty"]

            for word in words:
                # Deterministically project words to dimensions using SHA-256 slices
                h = hashlib.sha256(word.encode('utf-8')).hexdigest()
                for i in range(12):  # 12 slices of 4 hex chars = 48 chars
                    chunk = h[i*2 : i*2+4]
                    if not chunk:
                        continue
                    val = int(chunk, 16)
                    idx = val % 384
                    sign = -1.0 if (val % 2 == 0) else 1.0
                    vector[idx] += sign

            # Normalize to unit length
            norm = sum(x*x for x in vector) ** 0.5
            if norm > 0:
                vector = [x / norm for x in vector]
            else:
                vector[0] = 1.0

            embeddings.append(vector)
        return embeddings


# Determine embedding function based on availability
embedding_fn = None
try:
    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
    # Try to load the model to verify it works (with a timeout/fail-safe)
    embedding_fn = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    logger.info("ChromaDB using SentenceTransformers for embeddings.")
except Exception as exc:
    logger.warning("Could not initialize SentenceTransformerEmbeddingFunction: %s. Falling back to HashEmbeddingFunction.", exc)
    embedding_fn = HashEmbeddingFunction()


class VectorStore:
    """ChromaDB vector store manager for incident memory correlation."""

    _instance: Optional["VectorStore"] = None

    def __new__(cls, *args, **kwargs) -> "VectorStore":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self.host = settings.chroma.host
        self.port = settings.chroma.port
        self.collection_name = settings.chroma.collection

        logger.info("Connecting to ChromaDB client at %s:%d...", self.host, self.port)
        try:
            self.client = chromadb.HttpClient(host=self.host, port=self.port)
            # Fetch heartbeat to verify connection
            self.client.heartbeat()
            logger.info("Successfully connected to ChromaDB server.")
            
            # Get or create the collection with cosine similarity metric
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=embedding_fn,
                metadata={"hnsw:space": "cosine"}
            )
            self._initialized = True
            logger.info("ChromaDB collection '%s' is ready.", self.collection_name)
        except Exception as exc:
            logger.exception("Failed to connect to ChromaDB server")
            raise RuntimeError(f"ChromaDB connection error: {exc}") from exc

    def add_incident_report(self, alert_id: str, report_text: str, metadata: dict) -> None:
        """Add or update an incident report in ChromaDB.

        Args:
            alert_id: Unique identifier for the alert.
            report_text: Full text/markdown representation of the incident report.
            metadata: Filtering metadata (timestamp, severity, verdict, rule_description, src_ip, username).
        """
        if not self._initialized:
            logger.warning("ChromaDB client not initialized, skipping insert.")
            return

        # Sanitize metadata values to ensure they are primitives (ChromaDB does not support nested dicts/lists in metadata)
        sanitized_metadata = {}
        for k, v in metadata.items():
            if isinstance(v, (datetime, timezone)):
                sanitized_metadata[k] = v.isoformat()
            elif isinstance(v, (list, tuple, dict)):
                sanitized_metadata[k] = str(v)
            elif v is None:
                sanitized_metadata[k] = "none"
            else:
                sanitized_metadata[k] = v

        # Add timestamp if missing
        if "timestamp" not in sanitized_metadata:
            sanitized_metadata["timestamp"] = int(time.time())

        logger.info("Indexing incident report %s into ChromaDB...", alert_id)
        try:
            self.collection.upsert(
                ids=[alert_id],
                documents=[report_text],
                metadatas=[sanitized_metadata]
            )
            logger.info("Incident report %s indexed successfully.", alert_id)
        except Exception as exc:
            logger.error("Failed to index incident report %s into ChromaDB: %s", alert_id, exc)

    def search_similar_incidents(self, query_text: str, limit: int = 5) -> List[dict]:
        """Perform cosine similarity search for similar historical incidents.

        Args:
            query_text: Plain text search query.
            limit: Maximum number of matches to return.

        Returns:
            List of dicts representing matching documents and their similarity metadata.
        """
        if not self._initialized:
            logger.warning("ChromaDB client not initialized, returning empty results.")
            return []

        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=limit
            )
            
            output = []
            ids = results.get("ids", [[]])[0]
            documents = results.get("documents", [[]])[0]
            metadatas = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0]

            for i in range(len(ids)):
                output.append({
                    "id": ids[i],
                    "document": documents[i],
                    "metadata": metadatas[i],
                    "distance": distances[i],
                    # Convert distance to similarity score
                    "similarity": round(1.0 - distances[i], 4)
                })
            return output
        except Exception as exc:
            logger.error("Failed to search ChromaDB: %s", exc)
            return []

    def delete_old_incidents(self, days: int = 90) -> int:
        """Purge incident records older than the specified retention window.

        Args:
            days: Age threshold in days.

        Returns:
            Number of purged documents.
        """
        if not self._initialized:
            return 0

        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cutoff_timestamp = int(cutoff.timestamp())
            
            # Fetch items older than cutoff
            results = self.collection.get(
                where={"timestamp": {"$lt": cutoff_timestamp}}
            )
            
            ids = results.get("ids", [])
            if ids:
                logger.info("Purging %d incident records older than %d days from ChromaDB...", len(ids), days)
                self.collection.delete(ids=ids)
                return len(ids)
            return 0
        except Exception as exc:
            logger.error("Failed to purge old incidents from ChromaDB: %s", exc)
            return 0
