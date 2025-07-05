# src/main.py
from fastapi import FastAPI
from src.routers import validation_routers
import uvicorn

# Create the FastAPI application instance
app = FastAPI(
    title="Claim Extraction API",
    description="API for extracting claims from input data using the validation router.",
    version="1.0.0"
)

# Include the validation router under the /validation prefix
app.include_router(validation_routers.router, prefix="/validation")

# Optional: Define a root endpoint for a welcome message
@app.get("/health")
async def root():
    """
    Root endpoint for health check or welcome message.
    """
    return {"message": "Welcome to the Claim Extraction API. See /docs for API documentation."}


if __name__ == "__main__":
    # Run the application using Uvicorn server
    uvicorn.run(app, host="localhost", port=8001, log_level="info")