import os
import json
import requests
import time
import random
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from fake_useragent import UserAgent
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import threading
import websocket
import asyncio
import telegram
from telegram.ext import Updater

# Configure logging for Render
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def get_user_id_from_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload = parts[1]
        padding = '=' * (4 - len(payload) % 4)
        payload += padding
        decoded = base64.urlsafe_b64decode(payload)
        payload_json = json.loads(decoded)
        return payload_json.get('userId')
    except Exception as e:
        logger.error(f"Failed to decode token: {e}")
        return None

class TelegramNotifier:
    def __init__(self, bot_token: str, channel_id: str):
        self.bot = telegram.Bot(token=bot_token)
        self.channel_id = channel_id
        try:
            asyncio.run(self._test_channel())
            logger.info(f"Telegram initialized successfully for channel {self.channel_id}")
        except telegram.error.TelegramError as e:
            logger.warning(f"Telegram setup failed: {e}. Notifications disabled.")
            self.bot = None

    async def _test_channel(self):
        await self.bot.get_chat(chat_id=self.channel_id)

    async def send_message(self, message: str) -> bool:
        if not self.bot:
            return False
        try:
            await self.bot.send_message(chat_id=self.channel_id, text=message)
            logger.info(f"Telegram message sent: {message}")
            return True
        except telegram.error.TelegramError as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False

    def send_farming_update(self, source: str, volume: int, duration: int, progress: float) -> None:
        message = (
            f"🌾 *Farming Update* 🌾\nSource: {source}\nVolume: {volume} bytes\n"
            f"Duration: {duration}s\nProgress: {progress:.1f}%\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        asyncio.run(self.send_message(message))

    def send_points_balance(self, points: Optional[int]) -> None:
        message = (
            f"💰 *Points Balance Update* 💰\nPoints: {points if points is not None else 'Unknown'}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        asyncio.run(self.send_message(message))

class GrassWebSocketClient:
    def __init__(self, ws_url, auth_token, user_id):
        self.ws_url = ws_url
        self.auth_token = auth_token
        self.user_id = user_id
        self.ws = None
        self.running = False

    def on_open(self, ws):
        logger.info(f"WebSocket connection opened to {self.ws_url}")
        self.running = True
        auth_message = json.dumps({"userId": self.user_id, "type": "auth"})
        ws.send(auth_message)
        threading.Thread(target=self.send_ping, args=(ws,), daemon=True).start()

    def on_message(self, ws, message):
        logger.info(f"Received: {message}")
        data = json.loads(message)
        if "points" in data:
            logger.info(f"Current points from WebSocket: {data['points']}")

    def on_error(self, ws, error):
        logger.error(f"WebSocket error: {error}")

    def on_close(self, ws, close_status_code, close_msg):
        logger.info(f"WebSocket closed: {close_status_code} - {close_msg}")
        self.running = False

    def send_ping(self, ws):
        while self.running:
            try:
                ws.send(json.dumps({"type": "ping"}))
                logger.info("Sent ping")
                time.sleep(30)
            except Exception as e:
                logger.error(f"Ping failed: {e}")
                break

    def connect(self):
        self.ws = websocket.WebSocketApp(
            self.ws_url,
            header={"Authorization": f"Bearer {self.auth_token}", "User-Agent": UserAgent().random},
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )
        self.ws.run_forever()

class GrassFarmingClient:
    def __init__(self, for_encryption_only: bool = False):
        self.api_base_url = os.getenv("API_BASE_URL", "https://api.getgrass.io")
        encrypted_token = os.getenv("ENCRYPTED_AUTH_TOKEN")
        key = os.getenv("ENCRYPTION_KEY")
        if not (encrypted_token and key):
            raise ValueError("ENCRYPTED_AUTH_TOKEN and ENCRYPTION_KEY must be set in environment variables")
        self.auth_token = self._decrypt_token(encrypted_token, key)
        self.user_id = get_user_id_from_token(self.auth_token)
        if not self.user_id:
            raise ValueError("Could not extract user ID from token")
        
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_channel_id = os.getenv("TELEGRAM_CHANNEL_ID")
        
        self.ua = UserAgent()
        self.session_snapshots = []
        
        if not for_encryption_only and self.telegram_bot_token and self.telegram_channel_id:
            self.telegram = TelegramNotifier(self.telegram_bot_token, self.telegram_channel_id)
        else:
            self.telegram = None
        
        self.headers = {"Authorization": f"Bearer {self.auth_token}", "Content-Type": "application/json"}
        self.proxies = None

    def _generate_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"salt_", iterations=100000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _encrypt_token(self, token: str, key: str) -> str:
        f = Fernet(self._generate_key(key))
        return f.encrypt(token.encode()).decode()

    def _decrypt_token(self, encrypted_token: str, key: str) -> str:
        f = Fernet(self._generate_key(key))
        return f.decrypt(encrypted_token.encode()).decode()

    def _get_random_user_agent(self) -> str:
        return self.ua.random

    def get_points_balance(self) -> Optional[int]:
        endpoint = f"{self.api_base_url}/stats"
        self.headers["User-Agent"] = self._get_random_user_agent()

        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                points = data.get("points", None)
                if points is not None:
                    logger.info(f"Points balance: {points}")
                    if self.telegram:
                        self.telegram.send_points_balance(points)
                    return points
                else:
                    logger.warning("Points not found in stats response")
                    return None
            else:
                logger.error(f"Failed to get stats: {response.status_code} - {response.text}")
                return None
        except requests.RequestException as e:
            logger.error(f"Error getting stats: {e}")
            return None

def run_bot():
    try:
        client = GrassFarmingClient()
        ws_url = "wss://api.getgrass.io/v1/ws"
        ws_client = GrassWebSocketClient(ws_url, client.auth_token, client.user_id)
        ws_thread = threading.Thread(target=ws_client.connect, daemon=True)
        ws_thread.start()

        start_time = datetime.now()
        duration = timedelta(hours=24)

        while datetime.now() - start_time < duration:
            try:
                points = client.get_points_balance()
                if points is not None:
                    logger.info(f"Current points: {points}")
                if client.telegram:
                    client.telegram.send_farming_update("web", 1024, 300, ((datetime.now() - start_time).seconds / 86400) * 100)
                time.sleep(300)  # Check every 5 minutes
            except Exception as e:
                logger.error(f"Error in bot loop: {e}")
                time.sleep(60)
    except Exception as e:
        logger.error(f"Failed to initialize bot: {e}")
        raise

if __name__ == "__main__":
    if not os.getenv("ENCRYPTED_AUTH_TOKEN"):
        raw_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkJseGtPeW9QaWIwMlNzUlpGeHBaN2JlSzJOSEJBMSJ9.eyJ1c2VySWQiOiJmNzc2N2RjZS1hN2Y3LTQ0NWUtOTE2Mi02MDA6YWY4NTBiZjkiLCJlbWFpbCI6ImVuY2FybmFjaW9uamF5cGVlMjRAZ21haWwuY29tIiwic2NvcGUiOiJTRUxMRVIiLCJpYXQiOjE3NDI1NzA3MjEsIm5iZiI6MTc0MjU3MDcyMSwiZXhwIjoxNzczNjc0NzIxLCJhdWQiOiJ3eW5kLXVzZXJzIiwiaXNzIjoiaHR0cHM6Ly93eW5kLnMzLmFtYXpvbmF3cy5jb20vcHVibGljIn0.ehbLCZszUe_1uYQhQZxRNNBPyIC5Unlcv1SGu4mAcQv1RXAlht7nfDhWHbZwwTcpy_JBMvkuyxPOVSBRpT-vhLV4p8UqeTh_OzWbN56YdSwsL-gAT-FKZ3C9ZM70Dyx5xfndxOzPTEXYAGrSuSxhHQLMlZA_rHaxBsuI-TEuFgOdjvernMSASw0AbtjLk7_HYitg_D6lYtSvmuLTfIGo9WzAP8H57ukSJTDG2hbHnprcF75m7U_mB36eSeTbN-rsMXfYHB5etRJ28b45oOjdhfgaaTH41Eb8HsEyopxqSlFIRWHQ3RrXFquyde4-NvF04_9_rqecTe7L6JbGx1B9w"
        key = "MySuperSecretKey123!"
        client = GrassFarmingClient(for_encryption_only=True)
        encrypted_token = client._encrypt_token(raw_token, key)
        logger.info(f"Encrypted token: {encrypted_token}")
        logger.info("Set ENCRYPTED_AUTH_TOKEN and ENCRYPTION_KEY in your Render environment variables.")
    else:
        run_bot()
