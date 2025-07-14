# app/auth/dependencies.py

# Import tools for building web APIs and handling security
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# Import our User database model
from app.models.user import User

# Import the schema for how user data looks when returned
from app.schemas.user import UserResponse

# Sets up how to get an OAuth2 token from requests (from the "/token" endpoint)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency to find the current user based on their JWT token
def get_current_user(
    db, # Database session to interact with the database
    token: str = Depends(oauth2_scheme) # Get the token from the request
) -> UserResponse:
    """Gets the currently authenticated user from a JWT token."""

    # Define a standard error for invalid login attempts
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Try to get user ID from the token
    user_id = User.verify_token(token)
    # If no ID, token is bad
    if user_id is None:
        raise credentials_exception
    
    # Find the user in the database using the ID
    user = db.query(User).filter(User.id == user_id).first()
    # If user not found, something's wrong
    if user is None:
        raise credentials_exception
        
    # Return user data in the safe UserResponse format
    return UserResponse.model_validate(user)

# Dependency to get the current user AND check if they are active
def get_current_active_user(
    current_user: UserResponse = Depends(get_current_user) # First, get the current user
) -> UserResponse:
    """Gets the authenticated user and ensures they are active."""

    # If user is not active, raise an error
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    # If active, return the user
    return current_user