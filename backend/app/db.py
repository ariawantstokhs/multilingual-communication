import os
import logging
from typing import Optional
from contextlib import contextmanager

from dotenv import load_dotenv
from pymongo import MongoClient
import certifi
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_mongo_client: Optional[MongoClient] = None
_mongo_db: Optional[Database] = None


def _get_mongo_uri() -> str:
    """Get MongoDB URI from environment variables."""
    load_dotenv()
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        raise RuntimeError("MONGODB_URI is not set. Add it to backend/.env or environment.")
    return mongo_uri


def connect_to_mongo() -> Database:
    """
    Connect to MongoDB and return the database instance.
    Uses connection caching to avoid multiple connections.
    """
    global _mongo_client, _mongo_db
    if _mongo_db is not None:
        return _mongo_db

    try:
        mongo_uri = _get_mongo_uri()

        # Optional debugging/override flags from env
        tls_allow_invalid = os.getenv("MONGODB_TLS_ALLOW_INVALID_CERTS", "false").lower() in {"1", "true", "yes"}
        direct_connection = os.getenv("MONGODB_DIRECT_CONNECTION")
        direct_connection_flag = None if direct_connection is None else direct_connection.lower() in {"1", "true", "yes"}
        custom_ca_file = os.getenv("MONGODB_TLS_CA_FILE")

        # Connection options for better reliability
        mongo_kwargs = {
            "serverSelectionTimeoutMS": 10000,
            "connectTimeoutMS": 10000,
            "maxPoolSize": 50,
            "minPoolSize": 5,
            "maxIdleTimeMS": 30000,
            "tlsCAFile": custom_ca_file or certifi.where(),
        }

        if tls_allow_invalid:
            mongo_kwargs["tlsAllowInvalidCertificates"] = True
        if direct_connection_flag is not None:
            mongo_kwargs["directConnection"] = direct_connection_flag

        _mongo_client = MongoClient(mongo_uri, **mongo_kwargs)
        
        # Test the connection
        _mongo_client.admin.command('ping')
        
        db_name = os.getenv("MONGODB_DB", "app")
        _mongo_db = _mongo_client[db_name]
        
        logger.info(f"Successfully connected to MongoDB database: {db_name}")
        return _mongo_db
        
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise RuntimeError(f"MongoDB connection failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error connecting to MongoDB: {e}")
        raise


def get_db() -> Database:
    """Get the database instance, connecting if necessary."""
    if _mongo_db is None:
        return connect_to_mongo()
    
    # Test if connection is still alive
    try:
        _mongo_db.client.admin.command('ping')
        return _mongo_db
    except Exception:
        logger.warning("MongoDB connection lost, reconnecting...")
        close_mongo_connection()
        return connect_to_mongo()


def close_mongo_connection() -> None:
    """Close the MongoDB connection and reset global variables."""
    global _mongo_client, _mongo_db
    if _mongo_client is not None:
        try:
            _mongo_client.close()
            logger.info("MongoDB connection closed successfully")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")
        finally:
            _mongo_client = None
            _mongo_db = None


@contextmanager
def mongo_transaction():
    """
    Context manager for MongoDB transactions.
    Usage:
        with mongo_transaction() as session:
            collection.insert_one(doc, session=session)
            collection.update_one(filter, update, session=session)
    """
    db = get_db()
    with db.client.start_session() as session:
        with session.start_transaction():
            try:
                yield session
            except Exception:
                session.abort_transaction()
                raise


def health_check() -> dict:
    """Check MongoDB connection health."""
    try:
        db = get_db()
        # Ping the database
        db.client.admin.command('ping')
        
        # Get server info
        server_info = db.client.server_info()
        
        return {
            "status": "healthy",
            "database": db.name,
            "mongodb_version": server_info.get("version"),
            "connection_count": len(db.client.nodes)
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


# Usage examples and utilities
def get_collection(collection_name: str):
    """Get a collection from the database."""
    db = get_db()
    return db[collection_name]


def create_indexes():
    """Create common indexes for better performance."""
    try:
        # Example: create indexes for a users collection
        users_collection = get_collection("users")
        users_collection.create_index("email", unique=True)
        users_collection.create_index("created_at")
        
        logger.info("Database indexes created successfully")
    except Exception as e:
        logger.error(f"Error creating indexes: {e}")


# Graceful shutdown handler
def setup_cleanup():
    """Set up cleanup handlers for graceful shutdown."""
    import atexit
    import signal
    
    def cleanup():
        close_mongo_connection()
    
    # Register cleanup function
    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, lambda sig, frame: cleanup())
    signal.signal(signal.SIGINT, lambda sig, frame: cleanup())