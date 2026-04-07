from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Response
import re
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session

from database import engine, Base, get_db, SessionLocal
from models import User as DBUser

app = FastAPI(title="TrackBox: Lost and Found Management System")

# Security settings
SECRET_KEY = "my_super_secret_evsu_key"  # In production, use env variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_password_hash(password: str) -> str:
    if not password:
        return ""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password:
        return False
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Seed default admins if no users exist
    if not db.query(DBUser).filter(DBUser.email == "security@evsu.edu.ph").first():
        db.add(DBUser(first_name="Campus", last_name="Security", university_id="0000-0001", email="security@evsu.edu.ph", hashed_password=get_password_hash("Admin@123!"), role="Security Guard"))
    if not db.query(DBUser).filter(DBUser.email == "itfaculty@evsu.edu.ph").first():
        db.add(DBUser(first_name="IT", last_name="Faculty", university_id="0000-0002", email="itfaculty@evsu.edu.ph", hashed_password=get_password_hash("Admin@123!"), role="IT Faculty"))
    if not db.query(DBUser).filter(DBUser.email == "sao@evsu.edu.ph").first():
        db.add(DBUser(first_name="SAO", last_name="Admin", university_id="0000-0003", email="sao@evsu.edu.ph", hashed_password=get_password_hash("Admin@123!"), role="SAO Admin"))
    db.commit()
    db.close()

oauth = OAuth()
oauth.register(
    name='google',
    client_id='701122749258-u0kakqokhsfft8ol1gkmnesihcg1rku4.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Custom dependency to extract token from HttpOnly cookie
async def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    try:
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type = payload.get("type", "standard")
        if email is None:
            raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    except JWTError:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    
    user = db.query(DBUser).filter(DBUser.email == email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
        
    if token_type == "incomplete" and request.url.path != "/complete-profile":
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/complete-profile"})
        
    return user

@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse(request, "index.html")

# Google OAuth Routes
@app.get("/auth/login/google")
async def login_via_google(request: Request):
    redirect_uri = "http://localhost:8000/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        return templates.TemplateResponse(request, "login.html", {"error": "Google login failed: " + str(e)})
        
    user_info = token.get('userinfo')
    if not user_info:
        return templates.TemplateResponse(request, "login.html", {"error": "Failed to fetch user info from Google."})
        
    email = user_info.get("email", "")
    if not email.endswith("@evsu.edu.ph"):
        return templates.TemplateResponse(request, "login.html", {"error": "Only @evsu.edu.ph accounts are allowed via Google."})
        
    user = db.query(DBUser).filter(DBUser.email == email).first()
    if not user:
        new_user = DBUser(
            first_name=user_info.get("given_name", ""),
            middle_name="",
            last_name=user_info.get("family_name", ""),
            university_id=None,
            email=email,
            hashed_password=None,
            role="Student"
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        user = new_user
    
    if not user.university_id:
        access_token = create_access_token(data={"sub": email, "type": "incomplete"})
        res = RedirectResponse(url="/complete-profile", status_code=status.HTTP_302_FOUND)
        res.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        return res
        
    access_token = create_access_token(data={"sub": email})
    res = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    res.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    return res

@app.get("/complete-profile", response_class=HTMLResponse)
async def get_complete_profile(request: Request, current_user: DBUser = Depends(get_current_user)):
    return templates.TemplateResponse(request, "complete_profile.html", {"user": current_user})

@app.post("/complete-profile")
async def post_complete_profile(
    request: Request,
    university_id: str = Form(...),
    middle_name: Optional[str] = Form(""),
    current_user: DBUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    error = None
    if not re.match(r"^\d{4}-\d{4}$", university_id):
        error = "University ID must follow the correct format (e.g., 2024-0001)."
    
    existing = db.query(DBUser).filter(DBUser.university_id == university_id, DBUser.id != current_user.id).first()
    if existing:
        error = "This University ID is already registered."
        
    if error:
        return templates.TemplateResponse(request, "complete_profile.html", {"error": error, "user": current_user})
        
    current_user.university_id = university_id
    current_user.middle_name = middle_name
    db.commit()
    
    access_token = create_access_token(data={"sub": current_user.email})
    res = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    res.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    return res

@app.get("/register", response_class=HTMLResponse)
async def get_register(request: Request):
    return templates.TemplateResponse(request, "register.html")

@app.post("/register")
async def post_register(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    middle_name: Optional[str] = Form(""),
    university_id: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    role = "Student" 
    error = None
    if not email.endswith("@evsu.edu.ph"):
        error = "Please use a valid @evsu.edu.ph email address."
    elif db.query(DBUser).filter(DBUser.email == email).first():
        error = "Email is already registered."
    elif db.query(DBUser).filter(DBUser.university_id == university_id).first():
        error = "University ID is already registered."
    elif not re.match(r"^\d{4}-\d{4}$", university_id):
        error = "University ID must follow the correct format (e.g., 2024-0001)."
    elif password != confirm_password:
        error = "Passwords do not match."
    else:
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#\$%\^&\*\(\),\.\?\":\{\}\|\<\>]", password):
            error = "Password must be at least 8 characters long and include an uppercase letter, a number, and a special character."

    if error:
        return templates.TemplateResponse(request, "register.html", {
            "error": error, "first_name": first_name, "last_name": last_name, 
            "middle_name": middle_name, "university_id": university_id, "email": email
        })
    
    new_user = DBUser(
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        university_id=university_id,
        email=email,
        hashed_password=get_password_hash(password),
        role=role
    )
    db.add(new_user)
    db.commit()
    
    return RedirectResponse(url="/login?registered=1", status_code=status.HTTP_302_FOUND)

@app.get("/login", response_class=HTMLResponse)
async def get_login(request: Request, registered: Optional[int] = None):
    return templates.TemplateResponse(request, "login.html", {"registered": registered})

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login")
async def login_form_post(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(DBUser).filter(DBUser.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request, "login.html", {"error": "Incorrect email or password.", "email": email})
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    redirect_response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    redirect_response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return redirect_response

@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request, current_user: DBUser = Depends(get_current_user)):
    return templates.TemplateResponse(request, "dashboard.html", {"user": current_user})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
