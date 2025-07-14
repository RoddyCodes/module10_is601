# app/models/user.py

# Import standard Python modules for dates, unique IDs, and type hints
from datetime import datetime, timedelta
import uuid
from typing import Optional, Dict, Any

# Import SQLAlchemy components for defining database columns and models
from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID # Specific type for UUIDs in PostgreSQL
from sqlalchemy.orm import declarative_base # Base class for SQLAlchemy models
from sqlalchemy.exc import IntegrityError # For handling database errors like duplicate entries

# Import password hashing library
from passlib.context import CryptContext
# Import JWT (JSON Web Token) library for secure tokens
from jose import JWTError, jwt
# Import Pydantic for data validation
from pydantic import ValidationError

# Import Pydantic schemas from our application for user creation and response
from app.schemas.base import UserCreate # Schema for creating a new user
from app.schemas.user import UserResponse, Token # Schemas for user data response and authentication tokens

# Base class that our database models will inherit from
Base = declarative_base()

# Configure the password hashing method (using bcrypt, a strong hashing algorithm)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- IMPORTANT: These should be moved to a config file and kept secret in production! ---
# Secret key for signing JWT tokens. REPLACE "your-secret-key" with a long, random string.
SECRET_KEY = "your-secret-key"
# Algorithm used for signing JWT tokens
ALGORITHM = "HS256"
# How long access tokens are valid (in minutes)
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# --------------------------------------------------------------------------------------

# Define the User model, which maps to the 'users' table in the database
class User(Base):
    __tablename__ = 'users' # The name of the table in the database

    # Define table columns:
    # id: Unique identifier for each user (primary key, automatically generated UUID)
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # User's first name (text, cannot be empty)
    first_name = Column(String(50), nullable=False)
    # User's last name (text, cannot be empty)
    last_name = Column(String(50), nullable=False)
    # User's email (text, must be unique, cannot be empty)
    email = Column(String(120), unique=True, nullable=False)
    # User's unique username (text, must be unique, cannot be empty)
    username = Column(String(50), unique=True, nullable=False)
    # Hashed password (text, cannot be empty) - stores the *hashed* version
    password = Column(String(255), nullable=False)
    # Is user account active? (True/False, defaults to True)
    is_active = Column(Boolean, default=True, nullable=False)
    # Is user email verified? (True/False, defaults to False)
    is_verified = Column(Boolean, default=False, nullable=False)
    # Timestamp of the user's last login (can be empty)
    last_login = Column(DateTime, nullable=True)
    # Timestamp when the user account was created (defaults to current time)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    # Timestamp when the user account was last updated (updates automatically)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Defines how the User object appears when printed (for debugging)
    def __repr__(self):
        return f"<User(name={self.first_name} {self.last_name}, email={self.email})>"

    # Method to hash a plain password before storing it
    @staticmethod
    def hash_password(password: str) -> str:
        """Hashes a plain password using bcrypt."""
        return pwd_context.hash(password)

    # Method to check if a plain password matches the stored hashed password
    def verify_password(self, plain_password: str) -> bool:
        """Verifies a plain password against the stored hashed password."""
        return pwd_context.verify(plain_password, self.password)

    # Method to create a JWT access token for a user
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Creates a JWT access token."""
        to_encode = data.copy() # Copy data to include in token
        # Set token expiration time
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire}) # Add expiration to token data
        # Encode the token with the secret key and algorithm
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Method to verify and decode a JWT token to get the user's ID
    @staticmethod
    def verify_token(token: str) -> Optional[UUID]:
        """Verifies and decodes a JWT token."""
        try:
            # Decode the token using the secret key
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub") # Get the user ID from the token payload
            # Return user ID as UUID if found, otherwise None
            return uuid.UUID(user_id) if user_id else None
        except (JWTError, ValueError):
            # If token is invalid or expired, return None
            return None

    # Class method to handle new user registration
    @classmethod
    def register(cls, db, user_data: Dict[str, Any]) -> "User":
        """Registers a new user with validation."""
        try:
            # Check if password meets minimum length
            password = user_data.get('password', '')
            if len(password) < 6:
                raise ValueError("Password must be at least 6 characters long")
            
            # Check if username or email already exists in the database
            existing_user = db.query(cls).filter(
                (cls.email == user_data.get('email')) |
                (cls.username == user_data.get('username'))
            ).first()
            
            # If user with same email/username exists, raise an error
            if existing_user:
                raise ValueError("Username or email already exists")

            # Validate incoming user data using Pydantic schema
            user_create = UserCreate.model_validate(user_data)
            
            # Create a new User object, hashing the password before storing
            new_user = cls(
                first_name=user_create.first_name,
                last_name=user_create.last_name,
                email=user_create.email,
                username=user_create.username,
                password=cls.hash_password(user_create.password), # Hash password here!
                is_active=True,
                is_verified=False
            )
            
            db.add(new_user) # Add new user to the database session
            db.flush() # Send changes to DB (but don't commit yet)
            return new_user # Return the newly created user
            
        # Catch Pydantic validation errors (should be rare if schema is used earlier)
        except ValidationError as e:
            raise ValueError(str(e)) # pragma: no cover
        # Catch any other ValueErrors (like password length or existing user)
        except ValueError as e:
            raise e

    # Class method to authenticate a user during login
    @classmethod
    def authenticate(cls, db, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticates user and returns token with user data."""
        # Find user by username or email
        user = db.query(cls).filter(
            (cls.username == username) | (cls.email == username)
        ).first()

        # If user not found OR password doesn't match, return None
        if not user or not user.verify_password(password):
            return None # pragma: no cover

        # Update last login time and save to database
        user.last_login = datetime.utcnow()
        db.commit()

        # Create Pydantic models for the response data (user info and token)
        user_response = UserResponse.model_validate(user)
        token_response = Token(
            access_token=cls.create_access_token({"sub": str(user.id)}),
            token_type="bearer",
            user=user_response
        )

        # Return the token and user data as a dictionary
        return token_response.model_dump()