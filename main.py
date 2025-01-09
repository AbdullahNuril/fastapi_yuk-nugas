from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from pymongo import MongoClient, ASCENDING
import os
import uvicorn
from bson.objectid import ObjectId

# Konfigurasi Aplikasi
app = FastAPI(title="Backend Manajemen Tugas")

# Konfigurasi untuk melayani file statis (favicon dan file lainnya)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Tambahkan route khusus untuk favicon.ico
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/icon.ico")

# Konfigurasi Basis Data
client = MongoClient("mongodb+srv://14nuril04:Subscribe1434@cluster0.ocgjaaf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["banyak_tugas"]
users_collection = db["pengguna"]
tasks_collection = db["tugas"]
logs_collection = db["log_aktivitas"]

users_collection.create_index("email", unique=True)
tasks_collection.create_index([("status_tugas", ASCENDING)])
logs_collection.create_index("timestamp")

# Konfigurasi Keamanan
SECRET_KEY = "kelompok3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Model
class UserCreate(BaseModel):
    nama_pengguna: str
    email: str
    sandi: str
    peran: str = Field(..., pattern="^(admin|user)$")

class TaskCreate(BaseModel):
    nama_pemilik: str
    tgl_tugas_dibuat: datetime
    nama_tugas: str
    mapel_tugas: str
    deskripsi_tugas: str = ""
    tenggat_waktu: datetime
    status_tugas: str = Field("Belum", pattern="^(Belum|Sedang|Selesai)$")

class TaskUpdate(BaseModel):
    nama_tugas: str
    mapel_tugas: str
    deskripsi_tugas: str = ""
    tenggat_waktu: datetime
    status_tugas: str = Field(..., pattern="^(Belum|Sedang|Selesai)$")

# Fungsi Utilitas
def log_aktivitas(aksi: str, email_pengguna: str, detail: dict):
    logs_collection.insert_one({
        "aksi": aksi,
        "email_pengguna": email_pengguna,
        "detail": detail,
        "timestamp": datetime.utcnow()
    })

def verifikasi_sandi(sandi_plain, sandi_hash):
    return pwd_context.verify(sandi_plain, sandi_hash)

def hash_sandi(sandi):
    return pwd_context.hash(sandi)

def buat_token_akses(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def dapatkan_pengguna_saat_ini(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token tidak valid")
        user = users_collection.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Pengguna tidak ditemukan")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token tidak valid")

@app.get("/")
async def root():
    return {"greeting": "Selamat Datang!", "message": "Selamat datang di FastAPI Yuk Nugas!"}

# Rute
@app.post("/auth/register")
def daftar_pengguna(user: UserCreate):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email sudah terdaftar")
    hashed_password = hash_sandi(user.sandi)
    users_collection.insert_one({
        "nama_pengguna": user.nama_pengguna,
        "email": user.email,
        "sandi": hashed_password,
        "peran": user.peran
    })
    log_aktivitas("daftar", user.email, {"nama_pengguna": user.nama_pengguna, "peran": user.peran})
    return {"pesan": "Pengguna berhasil didaftarkan"}

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})
    if not user or not verifikasi_sandi(form_data.password, user["sandi"]):
        raise HTTPException(status_code=401, detail="Kredensial tidak valid")
    access_token = buat_token_akses({"sub": user["email"]})
    log_aktivitas("login", user["email"], {})
    return {"token_akses": access_token, "jenis_token": "bearer"}

@app.get("/users/me")
def baca_pengguna_saya(current_user: dict = Depends(dapatkan_pengguna_saat_ini)):
    log_aktivitas("ambil_info_pengguna", current_user["email"], {})
    return {
        "nama_pengguna": current_user["nama_pengguna"],
        "email": current_user["email"],
        "peran": current_user["peran"]
    }

@app.post("/tasks")
def buat_tugas(task: TaskCreate, current_user: dict = Depends(dapatkan_pengguna_saat_ini)):
    if current_user["peran"] != "user":
        raise HTTPException(status_code=403, detail="Hanya pengguna biasa yang dapat membuat tugas")

    data_tugas = {
        "nama_pemilik": task.nama_pemilik,
        "tgl_tugas_dibuat": task.tgl_tugas_dibuat,
        "nama_tugas": task.nama_tugas,
        "mapel_tugas": task.mapel_tugas,
        "deskripsi_tugas": task.deskripsi_tugas,
        "tenggat_waktu": task.tenggat_waktu,
        "status_tugas": task.status_tugas,
        "pemilik": current_user["email"],
        "dibuat_pada": datetime.utcnow()
    }
    tasks_collection.insert_one(data_tugas)
    log_aktivitas("buat_tugas", current_user["email"], data_tugas)
    return {"pesan": "Tugas berhasil dibuat"}

@app.get("/tasks")
def dapatkan_tugas(current_user: dict = Depends(dapatkan_pengguna_saat_ini)):
    if current_user["peran"] == "admin":
        tasks = list(tasks_collection.find())
    else:
        tasks = list(tasks_collection.find({"pemilik": current_user["email"]}))
    for task in tasks:
        task["_id"] = str(task["_id"])
    log_aktivitas("ambil_tugas", current_user["email"], {"peran": current_user["peran"]})
    return tasks

@app.put("/tasks/{task_id}")
def perbarui_tugas(task_id: str, task_update: TaskUpdate, current_user: dict = Depends(dapatkan_pengguna_saat_ini)):
    task = tasks_collection.find_one({"_id": ObjectId(task_id)})
    if not task or (current_user["peran"] != "admin" and task["pemilik"] != current_user["email"]):
        raise HTTPException(status_code=404, detail="Tugas tidak ditemukan atau akses ditolak")
    tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": task_update.dict()})
    log_aktivitas("perbarui_tugas", current_user["email"], {"task_id": task_id, **task_update.dict()})
    return {"pesan": "Tugas berhasil diperbarui"}

@app.delete("/tasks/{task_id}")
def hapus_tugas(task_id: str, current_user: dict = Depends(dapatkan_pengguna_saat_ini)):
    task = tasks_collection.find_one({"_id": ObjectId(task_id)})
    if not task or (current_user["peran"] != "admin" and task["pemilik"] != current_user["email"]):
        raise HTTPException(status_code=404, detail="Tugas tidak ditemukan atau akses ditolak")
    tasks_collection.delete_one({"_id": ObjectId(task_id)})
    log_aktivitas("hapus_tugas", current_user["email"], {"task_id": task_id})
    return {"pesan": "Tugas berhasil dihapus"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5432))
    uvicorn.run(app, host="0.0.0.0", port=port)