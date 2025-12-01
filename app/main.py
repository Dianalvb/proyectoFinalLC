from fastapi import FastAPI
from app.routers.crypto_router import router as crypto_router

app = FastAPI()

@app.get("/")
def root():
    return {"message": "API de encriptación funcionando"}

app.include_router(crypto_router, prefix="/crypto", tags=["Crypto"])
