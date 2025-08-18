from typing import Generic, TypeVar, Optional
from sqlmodel import SQLModel

# A generic type variable for our data payload
T = TypeVar('T')

class StandardResponse(SQLModel, Generic[T]):
    """
    A standardized response model for all API endpoints.
    """
    status: str = "success"
    message: str
    data: Optional[T] = None