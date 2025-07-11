from typing_extensions import Annotated
from fastapi import FastAPI, status, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import auth
from auth import get_current_user
from database import engine, SessionLocal
from sqlalchemy.orm import Session
import models
from fastapi.responses import JSONResponse
from auth import get_current_user, get_admin_user

# Create FastAPI app with metadata
app = FastAPI(
    title="Todo App API",
    description="A simple todo application with JWT authentication",
    version="1.0.0"
)

# Add CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include authentication routes
app.include_router(auth.router)

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Dependencies
def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]
admin_dependency = Annotated[dict, Depends(get_admin_user)] 

@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    """Root endpoint - API health check"""
    return {"message": "Todo App API is running", "status": "healthy"}

@app.get("/user", status_code=status.HTTP_200_OK)
async def get_user_info(user: user_dependency, db: db_dependency):
    """Get current authenticated user information"""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    # Get full user data from database
    user_data = db.query(models.Users).filter(models.Users.id == user["id"]).first()
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user['id']} not found"
        )
    
    return {
        "message": "User found",
        "user": {
            "id": user_data.id,
            "username": user_data.username,
            "is_admin": user_data.is_admin,  # ADDED: Include admin status
            "created_at": user_data.created_at
        }
    }

@app.get("/protected", status_code=status.HTTP_200_OK)
async def protected_route(user: user_dependency):
    """Example protected route that requires authentication"""
    return {
        "message": f"Hello {user['username']}! This is a protected route.",
        "user_id": user["id"]
    }
    
@app.get("/admin/status", status_code=status.HTTP_200_OK)
async def admin_status(user: admin_dependency):
    """Example admin-only route"""
    return {
        "message": f"Hello Admin {user['username']}! You have admin privileges.",
        "admin": True
    }

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler for unexpected errors"""
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "An unexpected error occurred",
            "status_code": 500
        }
    )