from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from typing import Annotated, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from starlette import status
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt

# Create router with prefix and tags for organization
router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# Load environment variables
load_dotenv()

# Get environment variables with validation
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")  # Default to HS256 if not set

# Validate required environment variables
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")

# Password hashing context
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

# Pydantic models for request/response validation
class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "testuser",
                "password": "testpassword123",
                "is_admin": False
            }
        }

class Token(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    id: int
    username: str
    
class UserListResponse(BaseModel):
    users: list[UserResponse]
    total: int
    page: int
    per_page: int

# Database dependency
def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

# Authentication functions (moved before routes that use them)
def authenticate_user(db: Session, username: str, password: str):
    """Verify user credentials against database"""
    try:
        # Find user by username
        user = db.query(Users).filter(Users.username == username).first()
        if not user:
            return False
        
        # Verify password hash
        if not bcrypt_context.verify(password, user.hashed_password):
            return False
        
        return user
    except Exception:
        return False

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    """Create JWT access token with user data and expiration"""
    encode = {
        "sub": username,
        "id": user_id,
        "exp": datetime.utcnow() + expires_delta
    }
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: Annotated[str, Depends(oauth2_bearer)], db: db_dependency):
    """Extract and validate user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        
        # Validate token data
        if username is None or user_id is None:
            raise credentials_exception
        
        # Verify user exists in database
        user = db.query(Users).filter(Users.username == username).first()
        if user is None:
            raise credentials_exception
        
        return {"username": username, "id": user_id}
        
    except JWTError:
        raise credentials_exception
    except Exception:
        raise credentials_exception
    
def get_admin_user(current_user: Annotated[dict, Depends(get_current_user)], db: db_dependency):
    """
    ADDED: Admin-only dependency that checks if authenticated user is an admin
    Requires user to be authenticated AND have admin privileges
    """
    # Get user from database to check admin status
    user = db.query(Users).filter(Users.username == current_user["username"]).first()
    
    # Check if user has admin privileges (assumes is_admin field exists in Users model)
    if not user or not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return current_user

# Routes
@router.post("/", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    """Create a new user with hashed password"""
    try:
        # Create user model with hashed password
        create_user_model = Users(
            username=create_user_request.username,
            hashed_password=bcrypt_context.hash(create_user_request.password),
            is_admin=create_user_request.is_admin
        )

        # Add to database
        db.add(create_user_model)
        db.commit()
        db.refresh(create_user_model)
        
        # Return user data (without password)
        return UserResponse(id=create_user_model.id, username=create_user_model.username)
        
    except IntegrityError:
        # Handle duplicate username
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{create_user_request.username}' already exists"
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating user"
        )

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    db: db_dependency
):
    """Authenticate user and return JWT token"""
    # Authenticate user credentials
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token with 30-minute expiration
    token = create_access_token(user.username, user.id, timedelta(minutes=30))
    
    return {"access_token": token, "token_type": "bearer"}


@router.get("/debug/user/{username}")
async def debug_user(username: str, db: db_dependency):
    """
    Debug route to verify user data in database.

    :param username: Username to search for
    :return: Dict with "found" key indicating if user was found, and "username" and "id" if found
    """
    user = db.query(Users).filter(Users.username == username).first()
    if user:
        return {"found": True, "username": user.username, "id": user.id}
    return {"found": False}


@router.post("/debug/verify")
async def debug_verify(username: str, password: str, db: db_dependency):
    """
    Debug route to verify a user's credentials.

    :param username: Username to verify
    :param password: Password to verify
    :return: Dict with "user_found" key indicating if user was found, and "password_valid" if found
    """
    user = db.query(Users).filter(Users.username == username).first()
    if user:
        is_valid = bcrypt_context.verify(password, user.hashed_password)
        return {"user_found": True, "password_valid": is_valid}
    return {"user_found": False}

@router.get("/admin/users", response_model=UserListResponse)
async def get_all_users(
    db: db_dependency,
    current_user: Annotated[dict, Depends(get_admin_user)],
    page: int = 1,
    per_page: int = 10
):
    """Admin route to get all users with pagination (admin auth required)"""
    # Calculate offset for pagination
    offset = (page - 1) * per_page
    
    # Get total count
    total = db.query(Users).count()
    
    # Get paginated users
    users = db.query(Users).offset(offset).limit(per_page).all()
    
    # Convert to response format (excludes passwords)
    user_list = [UserResponse(id=user.id, username=user.username) for user in users]
    
    return UserListResponse(
        users=user_list,
        total=total,
        page=page,
        per_page=per_page
    )