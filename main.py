from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from typing import Dict
from datetime import datetime, timedelta
import zoneinfo
import json
import jwt

# ➡️ 徹底拋棄 passlib，只使用原生官方安全加密套件 bcrypt
import bcrypt

# SQLAlchemy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, Text, DateTime, select

app = FastAPI()

# 1. 基礎設定
DATABASE_URL = "mysql+aiomysql://root:password@localhost:3306/chat_db"
SECRET_KEY = "super_secret_chat_key_2026"
ALGORITHM = "HS256"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# 2. 資料表模型定義
class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    # ➡️ bcrypt 生成的雜湊密碼在儲存時需要存成字串格式
    hashed_password = Column(String(100), nullable=False)

class ChatMessageModel(Base):
    __tablename__ = "chat_messages"
    id = Column(Integer, primary_key=True, index=True)
    channel = Column(String(50), index=True)
    nickname = Column(String(50))
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# 3. Token 簽發與驗證
def create_access_token(username: str):
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None

# 4. HTTP 路由：註冊與登入 (改用純 bcrypt 加密與比對)
@app.post("/register")
async def register(data: dict):
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="帳號密碼不能為空喔！")
        
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(UserModel).where(UserModel.username == username))
        if result.scalars().first():
            raise HTTPException(status_code=400, detail="此帳號已被註冊！")
            
        # ➡️ 這是純 bcrypt 的加密方法：將密碼轉為 bytes ➡️ 加鹽生成雜湊 ➡️ 解碼成字串存入 MySQL
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_pwd_bytes = bcrypt.hashpw(password_bytes, salt)
        hashed_pwd_str = hashed_pwd_bytes.decode('utf-8')

        new_user = UserModel(username=username, hashed_password=hashed_pwd_str)
        session.add(new_user)
        await session.commit()
    return {"message": "註冊成功"}

@app.post("/login")
async def login(data: dict):
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(UserModel).where(UserModel.username == username))
        user = result.scalars().first()
        
        if not user:
            raise HTTPException(status_code=400, detail="帳號或密碼錯誤！")
            
        # ➡️ 這是純 bcrypt 的驗證方法：將輸入的密碼與資料庫裡的雜湊字串轉為 bytes 進行安全比對
        password_bytes = password.encode('utf-8')
        db_hashed_bytes = user.hashed_password.encode('utf-8')
        
        if not bcrypt.checkpw(password_bytes, db_hashed_bytes):
            raise HTTPException(status_code=400, detail="帳號或密碼錯誤！")
            
        token = create_access_token(username)
        return {"token": token, "username": username}

# 5. WebSocket 頻道管理器
class ChannelManager:
    def __init__(self):
        self.channels: Dict[str, Dict[WebSocket, str]] = {}
        self.max_users_per_channel = 3 

    async def connect(self, websocket: WebSocket, channel: str, nickname: str) -> bool:
        await websocket.accept()
        if channel not in self.channels:
            self.channels[channel] = {}
        if len(self.channels[channel]) >= self.max_users_per_channel:
            await self.send_system_error(websocket, f"⚠️ #{channel} 頻道人數已滿")
            await websocket.close()
            return False
        self.channels[channel][websocket] = nickname
        return True

    def disconnect(self, websocket: WebSocket, channel: str):
        if channel in self.channels and websocket in self.channels[channel]:
            del self.channels[channel][websocket]
        if not self.channels[channel]:
            del self.channels[channel]

    async def save_message_to_db(self, channel: str, nickname: str, content: str):
        async with AsyncSessionLocal() as session:
            async with session.begin():
                new_msg = ChatMessageModel(channel=channel, nickname=nickname, content=content)
                session.add(new_msg)

    async def send_history_messages(self, websocket: WebSocket, channel: str):
        async with AsyncSessionLocal() as session:
            stmt = select(ChatMessageModel).where(ChatMessageModel.channel == channel).order_by(ChatMessageModel.id.desc()).limit(50)
            result = await session.execute(stmt)
            messages = result.scalars().all()
            messages.reverse() 
            for msg in messages:
                tw_time = msg.created_at.replace(tzinfo=zoneinfo.ZoneInfo("UTC")).astimezone(zoneinfo.ZoneInfo("Asia/Taipei")).strftime("%H:%M")
                chat_data = {"type": "CHAT_MSG", "nickname": msg.nickname, "content": msg.content, "time": tw_time, "is_system": False}
                await websocket.send_text(json.dumps(chat_data))

    async def broadcast_chat(self, channel: str, nickname: str, content: str, is_system: bool = False):
        if channel in self.channels:
            tw_time = datetime.now(zoneinfo.ZoneInfo("Asia/Taipei")).strftime("%H:%M")
            chat_data = {"type": "CHAT_MSG", "nickname": nickname, "content": content, "time": tw_time, "is_system": is_system}
            for connection in self.channels[channel].keys():
                await connection.send_text(json.dumps(chat_data))

    async def send_system_error(self, websocket: WebSocket, error_msg: str):
        error_data = {"type": "SYSTEM_ERROR", "content": error_msg}
        await websocket.send_text(json.dumps(error_data))

    async def broadcast_user_list(self, channel: str):
        if channel in self.channels:
            nicknames = list(self.channels[channel].values())
            user_list_data = {"type": "USER_LIST_UPDATE", "count": len(nicknames), "users": nicknames}
            for connection in self.channels[channel].keys():
                await connection.send_text(json.dumps(user_list_data))

manager = ChannelManager()

@app.get("/")
async def get():
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
# ➡️ 在 main.py 的 @app.get("/") 下方，補上這個新路由：
@app.get("/emoji.html")
async def get_emoji():
    with open("emoji.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.websocket("/ws/{channel}/{token}")
async def websocket_endpoint(websocket: WebSocket, channel: str, token: str):
    nickname = verify_token(token)
    if not nickname:
        await websocket.accept()
        await manager.send_system_error(websocket, "⚠️ 憑證無效，請重新登入")
        await websocket.close()
        return

    success = await manager.connect(websocket, channel, nickname)
    if not success:
        return 

    await manager.send_history_messages(websocket, channel)
    await manager.broadcast_chat(channel, "系統", f"🎉 【{nickname}】來到了 #{channel} 頻道", is_system=True)
    await manager.broadcast_user_list(channel)
    
    try:
        while True:
            data = await websocket.receive_text()
            await manager.save_message_to_db(channel, nickname, data)
            await manager.broadcast_chat(channel, nickname, data, is_system=False)
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
        await manager.broadcast_chat(channel, "系統", f"❌ 【{nickname}】離開了 #{channel} 頻道", is_system=True)
        await manager.broadcast_user_list(channel)
