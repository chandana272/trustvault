from fastapi import FastAPI

app = FastAPI(title="TrustVault")


@app.get("/api/health")
def health():
    return {"status": "ok"}
