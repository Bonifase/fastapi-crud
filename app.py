# Main application entry point

from fastapi import FastAPI
from api.auth import router as auth_router
from api.items import router as items_router

app = FastAPI()

app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(items_router, prefix="/api", tags=["items"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", reload=True)