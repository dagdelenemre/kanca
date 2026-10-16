"""Ortam değişkenlerinden okunan yapılandırma.

Tüm anahtarlar .env dosyasından gelir; .env.example şablon olarak kullanılır.
AI veya Telegram anahtarları boş bırakılırsa o katman sessizce devre dışı kalır.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Panel / API
    admin_token: str = "degistir-beni"
    base_domain: str = "oob.dagdelen.dev"   # yakalama (HTTP/DNS) kök alanı
    panel_domain: str = "panel.dagdelen.dev"
    public_ip: str = "127.0.0.1"            # DNS A yanıtlarında döndürülür
    max_body_bytes: int = 2 * 1024 * 1024   # 2 MB

    # DNS
    dns_udp_port: int = 53
    dns_tcp_port: int = 53

    # Depolama
    db_path: str = "data/kanca.db"

    # Gruplama penceresi (saniye): aynı token için bu süre içindeki
    # etkileşimler tek bildirimde toplanır.
    group_window_s: float = 5.0

    # AI (OpenAI uyumlu uç; ai_api_key boşsa AI kapalı)
    ai_base_url: str = "https://api.groq.com/openai/v1"
    ai_model: str = ""
    ai_api_key: str = ""

    # Telegram (token veya chat_id boşsa bildirim kapalı)
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    @property
    def ai_enabled(self) -> bool:
        return bool(self.ai_api_key and self.ai_model)

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)


@lru_cache
def get_settings() -> Settings:
    return Settings()
