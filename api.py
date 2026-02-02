import logging
import os
import traceback
from contextlib import asynccontextmanager
from typing import Optional

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, status, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("0xGuard-Cloud")

# --- GLOBAL STATE ---
# We use a dictionary to hold the model to ensure thread safety during lifespan events
ml_models = {}

# --- LIFESPAN MANAGER (Modern Startup Logic) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown events.
    Loads the ML model into memory before the first request is processed.
    """
    model_path = os.getenv("MODEL_PATH", "models/isolation_forest.pkl")
    try:
        logger.info(f"Attempting to load model from: {model_path}")
        ml_models["isolation_forest"] = joblib.load(model_path)
        logger.info("Model loaded successfully. Service is ready.")
    except FileNotFoundError:
        logger.critical(f"Model file not found at {model_path}. Service will be degraded.")
        ml_models["isolation_forest"] = None
    except Exception as e:
        logger.critical(f"Failed to load model: {str(e)}")
        ml_models["isolation_forest"] = None
    
    yield
    
    # Cleanup code (if needed) goes here
    ml_models.clear()
    logger.info("Service shutting down.")

# --- SECURITY CONFIGURATION ---
API_KEY_NAME = "X-API-Key"
# Default key for demo purposes; in production, set this env var!
API_KEY = os.getenv("API_KEY", "0xGUARD_DEMO_KEY_2026") 
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verifies the API key present in the header."""
    if api_key == API_KEY:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials"
    )

# --- APP INITIALIZATION ---
app = FastAPI(
    title="0xGuard Cloud Inference API",
    description="Enterprise API endpoint for real-time network anomaly detection using Isolation Forest.",
    version="3.1.0",
    lifespan=lifespan
)

# --- DATA MODELS (Request/Response Schemas) ---

class NetworkFlow(BaseModel):
    """Schema representing the network flow features required for inference."""
    dst_port: int = Field(..., description="Destination Port", example=443)
    protocol: int = Field(..., description="Protocol Number (e.g., 6 for TCP, 17 for UDP)", example=6)
    flow_packets: int = Field(..., description="Total packets in the flow", example=15)
    flow_bytes: int = Field(..., description="Total bytes in the flow", example=1200)
    flow_duration: float = Field(..., description="Duration of the flow in seconds", example=0.5)
    packet_rate: float = Field(..., description="Packets per second", example=30.0)
    byte_rate: float = Field(..., description="Bytes per second", example=2400.0)
    tcp_flags_sum: int = Field(..., description="Sum of TCP flags", example=2)

class AnalysisResponse(BaseModel):
    """Schema representing the analysis result."""
    status: str = Field(..., description="Security classification: SAFE or THREAT")
    action: str = Field(..., description="Recommended action: ALLOW or BLOCK")
    anomaly_score: float = Field(..., description="Raw model score. Negative values indicate anomalies.")
    details: str = Field(..., description="Additional processing information")

# --- ENDPOINTS ---

@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Liveness probe to verify service health."""
    if ml_models.get("isolation_forest") is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded"
        )
    return {"status": "online", "model": "loaded"}

@app.post(
    "/analyze", 
    response_model=AnalysisResponse, 
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_api_key)]
)
def analyze_traffic(flow: NetworkFlow):
    """
    Analyzes network flow data and returns a security classification.
    Requires a valid API Key in the 'X-API-Key' header.
    """
    model = ml_models.get("isolation_forest")
    
    if not model:
        logger.error("Analysis attempted while model is offline.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Inference service is currently unavailable"
        )

    try:
        # Prepare data frame maintaining exact feature order required by the model
        input_data = pd.DataFrame([{
            'Dst_Port': flow.dst_port,
            'Protocol': flow.protocol,
            'Flow_Packets': flow.flow_packets,
            'Flow_Bytes': flow.flow_bytes,
            'Flow_Duration': flow.flow_duration,
            'Packet_Rate': flow.packet_rate,
            'Byte_Rate': flow.byte_rate,
            'TCP_Flags_Sum': flow.tcp_flags_sum
        }])

        # Perform Inference
        score = model.decision_function(input_data)[0]

        # Business Logic
        # Note: Threshold is configurable. 0.00 is standard for Sklearn Isolation Forest.
        THRESHOLD = 0.00
        
        if score > THRESHOLD:
            status_label = "SAFE"
            action_label = "ALLOW"
        else:
            status_label = "THREAT"
            action_label = "BLOCK"
            logger.warning(f"Threat detected! Score: {score:.4f} | Features: {flow.dict()}")

        return AnalysisResponse(
            status=status_label,
            action=action_label,
            anomaly_score=float(score),
            details="Traffic analyzed successfully"
        )

    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        logger.debug(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal processing error during analysis"
        )