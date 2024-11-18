# main.py
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from typing import List, Optional
from pydantic import BaseModel
import jwt
import json
import mammoth
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import List
from geopy.distance import geodesic
from pydantic import BaseModel, Field

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./recipes.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "your-secret-key"  # Change this in production!
ALGORITHM = "HS256"
access_EXPIRE_MINUTES = 1440

class LocationCheck(BaseModel):
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)

class LocationResponse(BaseModel):
    allowed: bool
    message: str

class LocationSettings(BaseModel):
    latitude: float
    longitude: float
    radius_km: float

class RecipeCreate(BaseModel):
    name: str
    category: str
    file: str
    photo: Optional[str] = None

# Add this configuration after your JWT settings
# Configure the center point and radius of your allowed region
ALLOWED_REGION = {
    "center": {
        "latitude": 43.67671032048767,  # Example: San Francisco coordinates
        "longitude": -79.47068943825747,
    },
    "radius_km": 9  # Allowed radius in kilometers
}
# Database Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_superuser = Column(Boolean, default=False)
    recipes = relationship("Recipe", back_populates="owner")

class Recipe(Base):
    __tablename__ = "recipes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    category = Column(String)
    ingredients = Column(Text)  # Store as JSON string
    steps = Column(Text)  # Store as JSON string
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="recipes")

class Recipe_db(Base):
    __tablename__ = "recipe_db"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    category = Column(String)
    file = Column(Text)
    photo = Column(Text, nullable=True)


# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Models
class UserBase(BaseModel):
    email: str
    username: str

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    is_superuser: bool

    class Config:
        orm_mode = True

class UserResponse(BaseModel):
    user: UserOut

class RecipeBase(BaseModel):
    title: str
    description: str
    category: str
    ingredients: List[str]
    steps: List[str]

class Recipe_db_out(BaseModel):
    id: int
    name: str
    category: str
    file: str
    photo: str

    class Config:
        orm_mode = True

class RecipeOut(RecipeBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True

class Token(BaseModel):
    access: str
    token_type: str

# Helper functions


def is_location_allowed(lat: float, lng: float) -> bool:
    user_location = (lat, lng)
    center_point = (ALLOWED_REGION["center"]["latitude"], 
                   ALLOWED_REGION["center"]["longitude"])
    
    distance = geodesic(user_location, center_point).kilometers
    return distance <= ALLOWED_REGION["radius_km"]

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=access_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(OAuth2PasswordBearer(tokenUrl="token")), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except :
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# FastAPI app
app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://bigcityops.ca","http://localhost:3000","*"],  # Add your React app URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.post("/token/verify/", response_model=UserResponse)
async def verify_token(current_user: User = Depends(get_current_user)):
    """
    Verifies the token from Authorization header and returns user data if valid.
    Uses the existing get_current_user dependency which already handles token validation.
    """
    return {"user": current_user}

@app.post("/api/admin/upload-recipe")
async def upload_recipe(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    print(file.filename)
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if not file.filename.endswith('.docx'):
        raise HTTPException(status_code=400, detail="Only DOCX files are allowed")
    
    try:
        # Read the uploaded file
        content = await file.read()
        
        # Convert DOCX to HTML using mammoth
        result = mammoth.convert_to_html(content)
        html = result.value
        print(html)
        
        # Create recipe name from filename (without extension)
        name = file.filename.rsplit('.', 1)[0]
        
        # Create new recipe in database
        db = SessionLocal()
        new_recipe = Recipe_db(
            name=name,
            category="uncategorized",
            file=html,
            photo="null"
        )
        db.add(new_recipe)
        db.commit()
        db.refresh(new_recipe)
        
        return {"message": "Recipe uploaded successfully", "recipe": new_recipe}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/admin/recipes/{recipe_id}")
async def update_recipe(
    recipe_id: int,
    recipe: RecipeCreate,
    current_user: User = Depends(get_current_user)
):
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    db = SessionLocal()
    db_recipe = db.query(Recipe_db).filter(Recipe_db.id == recipe_id).first()
    if not db_recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    
    for key, value in recipe.dict().items():
        setattr(db_recipe, key, value)
    
    db.commit()
    db.refresh(db_recipe)
    return db_recipe

@app.delete("/api/admin/recipes/{recipe_id}")
async def delete_recipe(
    recipe_id: int,
    current_user: User = Depends(get_current_user)
):
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    db = SessionLocal()
    recipe = db.query(Recipe_db).filter(Recipe_db.id == recipe_id).first()
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    
    db.delete(recipe)
    db.commit()
    return {"message": "Recipe deleted successfully"}

@app.get("/api/admin/location-settings")
async def get_location_settings(current_user: User = Depends(get_current_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return {
        "latitude": ALLOWED_REGION["center"]["latitude"],
        "longitude": ALLOWED_REGION["center"]["longitude"],
        "radius_km": ALLOWED_REGION["radius_km"]
    }

@app.put("/api/admin/location-settings")
async def update_location_settings(
    settings: LocationSettings,
    current_user: User = Depends(get_current_user)
):
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Update the global settings
    ALLOWED_REGION["center"]["latitude"] = settings.latitude
    ALLOWED_REGION["center"]["longitude"] = settings.longitude
    ALLOWED_REGION["radius_km"] = settings.radius_km
    
    # In a production environment, you'd want to persist these changes to a database
    return {"message": "Location settings updated successfully"}

@app.post("/location/verify_location/", response_model=LocationResponse)
async def verify_location(
    location: LocationCheck,
    current_user: User = Depends(get_current_user)
):
    is_allowed = is_location_allowed(location.latitude, location.longitude)
    
    if not is_allowed:
        return LocationResponse(
            allowed=False,
            message="Access denied: Location is outside the allowed region"
        )
    
    return LocationResponse(
        allowed=True,
        message="Location verified successfully"
    )
# Auth endpoints
@app.post("/token", response_model=Token)
async def login_for_access(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access = create_access(data={"sub": user.username})
    return {"access": access, "token_type": "bearer"}

# User endpoints
@app.post("/users/", response_model=UserOut)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = User(
        email=user.email,
        username=user.username,
        hashed_password=get_password_hash(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/users/superuser/", response_model=UserOut)
def create_superuser(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = User(
        email=user.email,
        username=user.username,
        hashed_password=get_password_hash(user.password),
        is_superuser=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.delete("/recipes/{recipe_id}")
def delete_recipe(recipe_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if recipe is None:
        raise HTTPException(status_code=404, detail="Recipe not found")
    if not current_user.is_superuser and recipe.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this recipe")
    db.delete(recipe)
    db.commit()
    return {"message": "Recipe deleted"}


@app.get("/recipes/", response_model=List[Recipe_db_out])
def get_recipes(db: Session = Depends(get_db)):
    recipes = db.query(Recipe_db).all()
    return recipes

# Update the get_recipe endpoint
@app.get("/recipes/{recipe_id}", response_model=Recipe_db_out)
def get_recipe(recipe_id: int, db: Session = Depends(get_db)):
    recipe = db.query(Recipe_db).filter(Recipe_db.id == recipe_id).first()
    if recipe is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipe not found"
        )
    return recipe

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
