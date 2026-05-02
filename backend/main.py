import logging
import os
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routers import health, analysis, scan
from backend.services.feature_service import FeatureService
from backend.services.ml_service import MLService

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    handlers=[
                        logging.StreamHandler(),
                        logging.FileHandler("backend.log"),
                        ]
                    )
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: load ML model
    t0 = time.time()
    ml_service = MLService()
    try:
        ml_service.load()
        logger.info("ML model loaded in %.2fs", time.time() - t0)
    except Exception as e:
        logger.warning("ML model could not be loaded — running without model: %s", e)
    app.state.ml_service = ml_service
    app.state.feature_service = FeatureService()

    yield

    # Shutdown
    logger.info("Shutting down")


app = FastAPI(title="SmartHomeGuard API", version="0.1.0", lifespan=lifespan)

# CORS
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(health.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(scan.router, prefix="/api")
