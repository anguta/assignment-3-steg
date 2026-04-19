import io
import os
import json
import sqlite3
import secrets
from PIL import Image
 
from fastapi import FastAPI, Form, File, UploadFile, Header, HTTPException, Depends
from fastapi.responses import FileResponse
from passlib.context import CryptContext

from steg import encode, decode as steg_decode

app = FastAPI()
pwd = CryptContext(schemes=["bcrypt"])

UPLOAD_DIR = "/home/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

FILE_EXT = {
    'png':'image/png', 'jpg':'image/jpeg', 'jpeg':'image/jpeg',
    'bmp':'image/bmp', 'gif':'image/gif', 'wav':'audio/wav',
    'flac':'audio/flac', 'txt':'text/plain', 'ogg':'audio/ogg',
    'pdf':'application/pdf', 'mp4':'video/mp4', 'mov':'video/quicktime',
}

def database():
    db = sqlite3.connect("/home/steg.db")
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = database()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            token    TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS postings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            filename    TEXT NOT NULL,
            filetype    TEXT NOT NULL,
            s_param     INTEGER NOT NULL,
            l_param     INTEGER NOT NULL,
            c_param     TEXT NOT NULL
        );
    """)
    db.commit()
    db.close()

init_db()

def current_user(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="not logged in")
    token = authorization
    db = database()
    user = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    db.close()
    if not user:
        raise HTTPException(status_code=401, detail="invalid token")
    return user

@app.get('/')
def index():
    return FileResponse('index.html')

@app.get('/register')
def register_page():
    return FileResponse('register.html')

@app.get('/login')
def login_page():
    return FileResponse('login.html')

@app.get('/main')
def main_page():
    return FileResponse('main.html')

@app.post('/register')
def register(username: str = Form(...), password: str = Form(...)):
    db = database()
    if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        db.close()
        raise HTTPException(status_code=400, detail="username already taken")
    db.execute("INSERT INTO users (username, password) VALUES (?,?)", (username, pwd.hash(password)))
    db.commit()
    db.close()
    return {"message": "account created"}

@app.post('/login')
def login(username: str = Form(...), password: str = Form(...)):
    db = database()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user or not pwd.verify(password, user['password']):
        db.close()
        raise HTTPException(status_code=401, detail="invalid username or password")
    token = secrets.token_hex(32)
    db.execute("UPDATE users SET token=? WHERE id=?", (token, user['id']))
    db.commit()
    db.close()
    return {"token": token, "username": username}

@app.post('/logout')
def logout(current_user = Depends(current_user)):
    db = database()
    db.execute("UPDATE users SET token=NULL WHERE id=?", (current_user['id'],))
    db.commit()
    db.close()
    return {"message": "logged out"}

@app.post('/encode')
async def encode_post(
    user_file: UploadFile = File(...),
    message: UploadFile = File(...),
    s: int = Form(...),
    l: int = Form(...),
    c: str = Form(...),
    current_user = Depends(current_user)
):
    user_file_data = await user_file.read()
    message_data = await message.read()

    c_list = []
    for x in c.split(','):
        c_list.append(int(x.strip()))

    # have to turn these into bmp for it to work with steganography, i was having so much trouble converting them into png
    user_file_name, ext = os.path.splitext(user_file.filename)
    ext = ext.lower().lstrip('.')
    if ext in ('jpg', 'jpeg', 'gif'):
        img = Image.open(io.BytesIO(user_file_data))
        byte_arr = io.BytesIO()
        img.save(byte_arr, format='BMP')
        user_file_data = byte_arr.getvalue()
        ext = 'bmp'
        filetype = 'image/bmp'
        s = 434
    else:
        filetype = FILE_EXT.get(ext, 'application/octet-stream')

    try:
        steg_data = encode(user_file_data, message_data, s, l, c_list)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    db = database()
    check = db.execute(
        "INSERT INTO postings (user_id,filename,filetype,s_param,l_param,c_param) VALUES (?,?,?,?,?,?)", (current_user['id'], 'temporary', filetype, s, l, json.dumps(c_list))
    )
    post_id = check.lastrowid
    out_name = f"steg_{post_id}.{ext}"

    db.execute("UPDATE postings SET filename=? WHERE id=?", (out_name, post_id))
    db.commit()
    db.close()

    with open(os.path.join(UPLOAD_DIR, out_name), 'wb') as f:
        f.write(steg_data)
    
    return {"message": "posted successfully", "s": s, "l": l, "c": c_list}

@app.post('/decode')
async def decode_post(steg_file: UploadFile = File(...), s: int = Form(...), l: int = Form(...), c: str = Form(...)):
    steg_data = await steg_file.read()
    c_list = []
    for x in c.split(','):
        c_list.append(int(x.strip()))

    try:
        decoded = steg_decode(steg_data, s, l, c_list)
        return {"message": decoded.decode('utf-8'), "type": "text"}
    except UnicodeDecodeError:
        return {"message": decoded.hex(), "type": "binary"}
    except ValueError as e:
         raise HTTPException(status_code=400, detail=str(e))

@app.get('/postings')
def postings():
    db = database()
    rows = db.execute(
        "SELECT p.*, u.username FROM postings p JOIN users u ON p.user_id=u.id"
    ).fetchall()
    db.close()
    result = []
    for row in rows:
        result.append(dict(row))
    return result

@app.get('/postings/{post_id}')
def posting(post_id):
    db = database()
    row = db.execute(
        "SELECT p.*, u.username FROM postings p JOIN users u ON p.user_id=u.id WHERE p.id=?", (post_id,)
    ).fetchone()
    db.close()

    return dict(row)

@app.get('/postings/{post_id}/file')
def posting_file(post_id):
    db = database()
    row = db.execute("SELECT * FROM postings WHERE id=?", (post_id,)).fetchone()
    db.close()

    return FileResponse(os.path.join(UPLOAD_DIR, row['filename']), media_type=row['filetype'])

'''SOURCES
I used Claude AI for guidance and helping me with bugs. This was my first time working with a database in python and fastapi so I needed some guidance. There was no copying. 
Especially with the SQL and converting to bmp I needed the most guidance.
All work is my own.

I used the python code to help me get an idea where to start and what exactly stegonagrophy is.

https://thepythoncode.com/article/hide-secret-data-in-images-using-steganography-python
https://claude.ai
https://passlib.readthedocs.io/
https://fastapi.tiangolo.com/
https://graphics.stanford.edu/~seander/bithacks.html
https://github.com/scott-griffiths/bitstring
https://www-users.cs.umn.edu/~hoppernj/tc-stego.pdf
https://www.wired.com/story/steganography-hacker-lexicon/

these were used for guidance and reference. not copying full code implementations. 
so far all specifications have been met as stated in lecture and on the assignment pdf. 

Discuss how someone could find M or P, given only L

Someone could find M or P with only L by seeing how long it takes to go through the file and brute forcing.
And keep repeating that until they know S or C. S is relatively small and files always have their own fixed size. WIth that information the attacker can brute force all possible values to find M. 
By brute forcing S it can lead to M and P is
'''