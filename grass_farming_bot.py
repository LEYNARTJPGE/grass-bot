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
import asyncio
import telegram
from telegram.ext import Updater

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("grass_bot.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class TelegramNotifier:
    def __init__(self, bot_token: str, channel_id: str):
        if not bot_token:
            raise ValueError("Telegram bot token is required")
        self.bot = telegram.Bot(token=bot_token)
        self.channel_id = channel_id

    async def send_message(self, message: str) -> bool:
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

class GrassFarmingClient:
    def __init__(self, auth_token: Optional[str] = None, encryption_key: Optional[str] = None, for_encryption_only: bool = False):
        self.api_base_url = os.getenv("API_BASE_URL", "https://api.getgrass.io")
        if auth_token and encryption_key:
            self.auth_token = auth_token  # Use provided token for encryption
        else:
            encrypted_token = os.getenv("ENCRYPTED_AUTH_TOKEN")
            key = os.getenv("ENCRYPTION_KEY")
            if not (encrypted_token and key):
                raise ValueError("ENCRYPTED_AUTH_TOKEN and ENCRYPTION_KEY must be set in environment variables")
            self.auth_token = self._decrypt_token(encrypted_token, key)
        
        self.proxy_address = os.getenv("PROXY_ADDRESS", "127.0.0.1")
        self.proxy_port = int(os.getenv("PROXY_PORT", 8080))
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_channel_id = os.getenv("TELEGRAM_CHANNEL_ID")
        
        self.ua = UserAgent()
        self.session_snapshots = []
        
        # Only initialize Telegram if not just encrypting
        if not for_encryption_only:
            if not (self.telegram_bot_token and self.telegram_channel_id):
                logger.warning("Telegram bot token or channel ID missing; notifications disabled")
                self.telegram = None
            else:
                self.telegram = TelegramNotifier(self.telegram_bot_token, self.telegram_channel_id)
        else:
            self.telegram = None
        
        self.headers = {"Authorization": f"Bearer {self.auth_token}", "Content-Type": "application/json"}
        self.proxies = {"http": f"http://{self.proxy_address}:{self.proxy_port}", "https": f"http://{self.proxy_address}:{self.proxy_port}"}
        self.fallback_proxies = {"http": "http://20.235.107.191:80", "https": "http://20.235.107.191:80"}

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

    def _capture_snapshot(self, request_data: Dict[str, Any], response: Any, status: str) -> None:
        snapshot = {
            "timestamp": str(datetime.now()),
            "request": request_data,
            "response": response.text if response else None,
            "status": status,
            "proxy_used": self.proxies if response else "Fallback or None"
        }
        self.session_snapshots.append(snapshot)
        logger.info(f"Snapshot captured: {status}")

    def _test_proxy(self, proxies: Dict[str, str]) -> bool:
        test_url = "https://api.ipify.org"
        try:
            response = requests.get(test_url, proxies=proxies, timeout=5)
            response.raise_for_status()
            logger.info(f"Proxy {proxies['http']} is working. IP: {response.text}")
            return True
        except requests.RequestException as e:
            logger.warning(f"Proxy {proxies['http']} failed: {e}")
            return False

    def farm_points(self, source: str, volume: int, duration: int) -> Optional[Dict[str, Any]]:
        endpoint = f"{self.api_base_url}/traffic/farm"
        payload = {"source": source, "volume": volume, "duration": duration}
        self.headers["User-Agent"] = self._get_random_user_agent()

        logger.info(f"Starting farming: Source={source}, Volume={volume}, Duration={duration}s")
        if self.telegram:
            self.telegram.send_farming_update(source, volume, duration, 0.0)

        active_proxies = self.proxies if self._test_proxy(self.proxies) else self.fallback_proxies
        if not self._test_proxy(active_proxies):
            logger.warning("Both proxies failed. Using direct connection.")
            active_proxies = None

        request_data = {"endpoint": endpoint, "payload": payload, "headers": self.headers}
        response = None

        try:
            response = requests.post(endpoint, headers=self.headers, data=json.dumps(payload),
                                    proxies=active_proxies, timeout=10)
            status_code = response.status_code

            if status_code in (200, 201):
                data = response.json()
                self._capture_snapshot(request_data, response, "Success")
                logger.info(f"Farming successful: {data}")
                self._simulate_farming_progress(source, volume, duration)
                points = data.get("points_earned", None)
                if points is not None and self.telegram:
                    self.telegram.send_points_balance(points)
                return data
            elif status_code == 401:
                self._capture_snapshot(request_data, response, "Unauthorized")
                logger.error("Error 401: Unauthorized")
                return None
            elif status_code == 403:
                self._capture_snapshot(request_data, response, "Forbidden")
                logger.error("Error 403: Forbidden")
                return None
            elif status_code == 429:
                self._capture_snapshot(request_data, response, "Rate Limited")
                logger.warning("Error 429: Too Many Requests")
                time.sleep(60)
                return None
            else:
                self._capture_snapshot(request_data, response, f"Status {status_code}")
                logger.error(f"Unexpected status code {status_code}: {response.text}")
                return None

        except requests.RequestException as e:
            self._capture_snapshot(request_data, None, f"Request Failed: {str(e)}")
            logger.error(f"Request failed: {e}")
            return None

    def _simulate_farming_progress(self, source: str, volume: int, duration: int) -> None:
        start_time = time.time()
        interval = max(1, duration // 10)
        while time.time() - start_time < duration:
            elapsed = int(time.time() - start_time)
            progress = min(100, (elapsed / duration) * 100)
            logger.info(f"Farming in progress: {progress:.1f}% complete ({elapsed}/{duration}s)")
            if self.telegram:
                self.telegram.send_farming_update(source, volume, duration, progress)
            time.sleep(interval)
        logger.info(f"Farming completed: 100% ({duration}/{duration}s)")
        if self.telegram:
            self.telegram.send_farming_update(source, volume, duration, 100.0)

    def get_points_balance(self) -> Optional[int]:
        endpoint = f"{self.api_base_url}/user/points"
        self.headers["User-Agent"] = self._get_random_user_agent()
        active_proxies = self.proxies if self._test_proxy(self.proxies) else self.fallback_proxies

        try:
            response = requests.get(endpoint, headers=self.headers, proxies=active_proxies, timeout=10)
            if response.status_code == 200:
                data = response.json()
                points = data.get("points", None)
                logger.info(f"Points balance: {points}")
                if self.telegram:
                    self.telegram.send_points_balance(points)
                return points
            else:
                logger.error(f"Failed to get points: {response.status_code}")
                return None
        except requests.RequestException as e:
            logger.error(f"Error getting points: {e}")
            return None

def run_bot():
    client = GrassFarmingClient()
    start_time = datetime.now()
    duration = timedelta(hours=24)

    while datetime.now() - start_time < duration:
        try:
            client.farm_points(source="web", volume=1024, duration=300)
            points = client.get_points_balance()
            logger.info(f"Cycle completed. Points: {points}")
            time.sleep(300)
        except Exception as e:
            logger.error(f"Bot crashed: {e}. Restarting in 60 seconds...")
            time.sleep(60)
            continue

if __name__ == "__main__":
    # Encrypt token for initial setup (run once)
    raw_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkJseGtPeW9QaWIwMlNzUlpGeHBaN2JlSzJOSEJBMSJ9.eyJ1c2VySWQiOiJmNzc2N2RjZS1hN2Y3LTQ0NWUtOTE2Mi02MDA2YWY4NTBiZjkiLCJlbWFpbCI6ImVuY2FybmFjaW9uamF5cGVlMjRAZ21haWwuY29tIiwic2NvcGUiOiJTRUxMRVIiLCJpYXQiOjE3NDI1NzA3MjEsIm5iZiI6MTc0MjU3MDcyMSwiZXhwIjoxNzczNjc0NzIxLCJhdWQiOiJ3eW5kLXVzZXJzIiwiaXNzIjoiaHR0cHM6Ly93eW5kLnMzLmFtYXpvbmF3cy5jb20vcHVibGljIn0.ehbLCZszUe_1uYQhQZxRNNBPyIC5Unlcv1SGu4mAcQv1RXAlht7nfDhWHbZwwTcpy_JBMvkuyxPOVSBRpT-vhLV4p8UqeTh_OzWbN56YdSwsL-gAT-FKZ3C9ZM70Dyx5xfndxOzPTEXYAGrSuSxhHQLMlZA_rHaxBsuI-TEuFgOdjvernMSASw0AbtjLk7_HYitg_D6lYtSvmuLTfIGo9WzAP8H57ukSJTDG2hbHnprcF75m7U_mB36eSeTbN-rsMXfYHB5etRJ28b45oOjdhfgaaTH41Eb8HsEyopxqSlFIRWHQ3RrXEFquyde4-NvF04_9_rqecTe7L6JbGx1B9w"
    key = "MySuperSecretKey123!"
    client = GrassFarmingClient(auth_token=raw_token, encryption_key=key, for_encryption_only=True)  # Skip Telegram init
    encrypted_token = client._encrypt_token(raw_token, key)
    logger.info(f"Encrypted token: {encrypted_token}")
    logger.info("Set ENCRYPTED_AUTH_TOKEN and ENCRYPTION_KEY in your Render environment variables.")
    # Uncomment the next line to run the bot after setting environment variables
    # run_bot()
