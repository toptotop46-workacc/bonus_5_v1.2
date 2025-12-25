#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import random
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from loguru import logger
from web3 import Web3

# Позволяет запускать файл напрямую: `python modules/mint4season.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    root_s = str(PROJECT_ROOT)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)


def load_private_key(key_index: int = 0) -> str:
    """
    Загружает приватный ключ из файла keys.txt.

    Args:
        key_index: Индекс ключа (по умолчанию 0 - первый ключ)

    Returns:
        Приватный ключ как строка

    Raises:
        FileNotFoundError: Если файл не найден
        ValueError: Если ключ не найден или неверный формат
    """
    import re

    keys_file = PROJECT_ROOT / "keys.txt"
    if not keys_file.exists():
        raise FileNotFoundError(
            f"Файл {keys_file} не найден. "
            "Создайте файл и укажите в нем приватные ключи."
        )

    keys = []
    with open(keys_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Пропускаем комментарии и пустые строки
            if line and not line.startswith("#"):
                # Проверяем формат приватного ключа (64 символа hex)
                if re.match(r"^0x[a-fA-F0-9]{64}$", line):
                    keys.append(line)
                elif re.match(r"^[a-fA-F0-9]{64}$", line):
                    keys.append("0x" + line)

    if not keys:
        raise ValueError(f"В файле {keys_file} не найдено действительных приватных ключей")

    if key_index < 0 or key_index >= len(keys):
        raise ValueError(
            f"Индекс ключа {key_index} вне диапазона (доступно ключей: {len(keys)})"
        )

    return keys[key_index]


def load_all_keys() -> list[str]:
    """
    Загружает все приватные ключи из файла keys.txt.

    Returns:
        Список всех приватных ключей

    Raises:
        FileNotFoundError: Если файл не найден
        ValueError: Если не найдено действительных ключей
    """
    import re

    keys_file = PROJECT_ROOT / "keys.txt"
    if not keys_file.exists():
        raise FileNotFoundError(
            f"Файл {keys_file} не найден. "
            "Создайте файл и укажите в нем приватные ключи."
        )

    keys = []
    with open(keys_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Пропускаем комментарии и пустые строки
            if line and not line.startswith("#"):
                # Проверяем формат приватного ключа (64 символа hex)
                if re.match(r"^0x[a-fA-F0-9]{64}$", line):
                    keys.append(line)
                elif re.match(r"^[a-fA-F0-9]{64}$", line):
                    keys.append("0x" + line)

    if not keys:
        raise ValueError(f"В файле {keys_file} не найдено действительных приватных ключей")

    return keys


def load_adspower_api_key() -> str:
    """
    Загружает API ключ AdsPower из файла adspower_api_key.txt.

    Returns:
        API ключ как строка

    Raises:
        FileNotFoundError: Если файл не найден
        ValueError: Если файл пуст или ключ не найден
    """
    api_key_file = PROJECT_ROOT / "adspower_api_key.txt"

    if not api_key_file.exists():
        raise FileNotFoundError(
            f"Файл {api_key_file} не найден. "
            "Создайте файл и укажите в нем API ключ AdsPower."
        )

    with open(api_key_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]

    if not lines:
        raise ValueError(
            f"Файл {api_key_file} пуст. Укажите API ключ AdsPower в файле."
        )

    api_key = lines[0]  # Берем первую непустую строку

    if not api_key or api_key == "your_adspower_api_key_here":
        raise ValueError(
            f"В файле {api_key_file} указан шаблонный ключ. "
            "Замените его на реальный API ключ AdsPower."
        )

    return api_key


# === Конфиг Portal API ===
PORTAL_API_URL = "https://portal.soneium.org/api/profile/calculator"
PROXY_FILE = PROJECT_ROOT / "proxy.txt"

# === Конфиг RPC для Soneium ===
RPC_URL_DEFAULT = "https://soneium-rpc.publicnode.com"
CHAIN_ID = 1868

# === Конфиг NFT Season 4 ===
NFT_CONTRACT_ADDRESS = "0x17121f9a7041FFe3EF248F7b84658d9229bad64f"
OPENSEA_URL = "https://opensea.io/collection/soneium-score-season4-badge/overview"
RABBY_EXTENSION_ID = "acmacodkjbdgmoleebolmdjonilkdbch"

# === Периоды клайма для Season 4 (UTC) ===
SEASON4_HIGH_SCORE_PERIOD_START = datetime(2025, 12, 22, 0, 0, 0, tzinfo=timezone.utc)  # Dec 22, 2025 00:00:00 UTC
SEASON4_HIGH_SCORE_PERIOD_END = datetime(2026, 1, 7, 23, 59, 59, tzinfo=timezone.utc)   # Jan 7, 2026 23:59:59 UTC
SEASON4_LOW_SCORE_PERIOD_START = datetime(2026, 1, 8, 0, 0, 0, tzinfo=timezone.utc)     # Jan 8, 2026 00:00:00 UTC

# Минимальный порог поинтов для eligibility
SEASON4_MIN_SCORE = 80

# === Конфиг базы данных ===
DB_PATH = PROJECT_ROOT / "mint4season.db"


@dataclass(frozen=True)
class ProxyEntry:
    host: str
    port: int
    username: str
    password: str

    @property
    def http_url(self) -> str:
        # Прокси в формате http://user:pass@host:port
        user = self.username.replace("@", "%40")
        pwd = self.password.replace("@", "%40")
        return f"http://{user}:{pwd}@{self.host}:{self.port}"

    @property
    def safe_label(self) -> str:
        return f"{self.host}:{self.port}"


def _parse_proxy_line(line: str) -> ProxyEntry | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":", 3)
    if len(parts) != 4:
        return None
    host, port_s, username, password = [p.strip() for p in parts]
    if not host or not port_s:
        return None
    try:
        port = int(port_s)
    except ValueError:
        return None
    return ProxyEntry(host=host, port=port, username=username, password=password)


def load_proxies() -> list[ProxyEntry]:
    """Загружает прокси из файла proxy.txt"""
    if not PROXY_FILE.exists():
        return []
    proxies: list[ProxyEntry] = []
    for raw in PROXY_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        p = _parse_proxy_line(raw)
        if p:
            proxies.append(p)
    return proxies


def _fetch_portal_score_data(address: str, max_attempts: int = 30) -> Optional[list]:
    """
    Запрашивает данные score через Portal API с ротацией прокси.

    Args:
        address: Адрес кошелька
        max_attempts: Максимальное количество попыток

    Returns:
        Список данных score или None при ошибке
    """
    proxies_all = load_proxies()
    session = requests.Session()

    attempts = max(1, int(max_attempts))
    pool: list[ProxyEntry] = proxies_all[:]
    random.shuffle(pool)

    for attempt in range(1, attempts + 1):
        p: Optional[ProxyEntry] = None
        proxies_cfg: Optional[dict[str, str]] = None

        if proxies_all:
            if not pool:
                pool = proxies_all[:]
                random.shuffle(pool)
            p = pool.pop()
            proxies_cfg = {"http": p.http_url, "https": p.http_url}
        else:
            p = None
            proxies_cfg = None

        try:
            r = session.get(
                PORTAL_API_URL,
                params={"address": address},
                timeout=30,
                proxies=proxies_cfg,
                headers={
                    "accept": "application/json",
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
            )

            if r.status_code in (429, 500, 502, 503, 504):
                raise RuntimeError(f"portal http {r.status_code}")

            r.raise_for_status()
            data = r.json()

            if not isinstance(data, list):
                raise RuntimeError(f"Неожиданный формат ответа portal: {type(data)}")

            return data

        except Exception as e:
            logger.debug(
                "[PORTAL] attempt {}/{} proxy={} err={}",
                attempt,
                attempts,
                (p.safe_label if p else "none"),
                e,
            )
            if attempt < attempts:
                time.sleep(random.uniform(0.4, 1.2))

    return None


def _get_season4_data(score_data: list) -> Optional[dict]:
    """
    Извлекает данные Season 4 из ответа Portal API.

    Args:
        score_data: Список данных score из Portal API

    Returns:
        Словарь с данными Season 4 или None
    """
    if not isinstance(score_data, list):
        return None

    for item in score_data:
        if not isinstance(item, dict):
            continue
        if item.get("season") == 4:
            return item

    return None


def _determine_season4_eligibility_status(totalScore: int) -> dict:
    """
    Определяет статус eligibility на основе количества поинтов и текущей даты (UTC).

    Логика:
    - totalScore >= 84: период Dec 22, 2025 - Jan 7, 2026 (UTC)
    - totalScore >= 80 и totalScore <= 83: период с Jan 8, 2026 (UTC)
    - totalScore < 80: not_eligible

    Args:
        totalScore: Общее количество поинтов Season 4

    Returns:
        dict с полями: status, message, claimingPeriod
    """
    now = datetime.now(timezone.utc)  # Текущее время в UTC

    if totalScore >= 84:
        # Высокий скор: Dec 22, 2025 - Jan 7, 2026 (UTC)
        claimingPeriod = "Dec 22 - Jan 7"

        if now > SEASON4_HIGH_SCORE_PERIOD_END:
            return {
                "status": "period_ended",
                "message": "Claiming period ended",
                "claimingPeriod": claimingPeriod,
            }
        elif now < SEASON4_HIGH_SCORE_PERIOD_START:
            return {
                "status": "waiting",
                "message": "Claim available from Dec 22",
                "claimingPeriod": claimingPeriod,
            }
        else:
            return {
                "status": "eligible",
                "message": "Eligible for claim",
                "claimingPeriod": claimingPeriod,
            }

    elif totalScore >= SEASON4_MIN_SCORE and totalScore <= 83:
        # Низкий скор: с Jan 8, 2026 (UTC)
        claimingPeriod = "Jan 8 - ..."

        if now < SEASON4_LOW_SCORE_PERIOD_START:
            return {
                "status": "waiting",
                "message": "Claim available from Jan 8",
                "claimingPeriod": claimingPeriod,
            }
        else:
            return {
                "status": "eligible",
                "message": "Eligible for claim",
                "claimingPeriod": claimingPeriod,
            }

    else:
        # totalScore < 80: не eligible
        return {
            "status": "not_eligible",
            "message": "Not eligible to claim (minimum 80 points required)",
            "claimingPeriod": None,
        }


def check_season4_eligibility(address: str) -> dict:
    """
    Проверяет eligibility кошелька для клайма Season 4.

    Args:
        address: Адрес кошелька (checksum format)

    Returns:
        dict с полями:
        - status: 'eligible' | 'waiting' | 'not_eligible' | 'period_ended' | 'no_data'
        - message: строка с описанием статуса
        - totalScore: количество поинтов (0 если нет данных)
        - claimingPeriod: строка с периодом клайма (например, "Dec 22 - Jan 7")
        - season4Data: данные Season 4 из API (если доступны)
        - error: строка с ошибкой (если есть)
    """
    try:
        # 1. Запрос к Portal API через прокси (с retry логикой)
        score_data = _fetch_portal_score_data(address)

        if not score_data:
            return {
                "status": "no_data",
                "message": "Не удалось получить данные",
                "totalScore": 0,
                "claimingPeriod": None,
                "season4Data": None,
                "error": "Portal API недоступен",
            }

        # 2. Извлечение данных Season 4
        season4_data = _get_season4_data(score_data)

        if not season4_data:
            return {
                "status": "no_data",
                "message": "Данные Season 4 не найдены",
                "totalScore": 0,
                "claimingPeriod": None,
                "season4Data": None,
                "error": "Season 4 data not found in API response",
            }

        # 3. Получение totalScore
        total_score = season4_data.get("totalScore", 0)

        # 4. Определение статуса на основе поинтов и даты
        eligibility_status = _determine_season4_eligibility_status(total_score)

        return {
            "status": eligibility_status["status"],
            "message": eligibility_status["message"],
            "totalScore": total_score,
            "claimingPeriod": eligibility_status.get("claimingPeriod"),
            "season4Data": season4_data,
            "error": None,
        }

    except Exception as e:
        return {
            "status": "no_data",
            "message": "Ошибка при проверке",
            "totalScore": 0,
            "claimingPeriod": None,
            "season4Data": None,
            "error": str(e),
        }


def check_nft_balance(address: str) -> bool:
    """
    Проверяет, есть ли у кошелька NFT Season 4 (баланс > 0).

    Args:
        address: Адрес кошелька (checksum format)

    Returns:
        True если есть NFT, False если нет
    """
    try:
        w3 = Web3(Web3.HTTPProvider(RPC_URL_DEFAULT, request_kwargs={"timeout": 30}))

        if not w3.is_connected():
            logger.warning("RPC недоступен при проверке баланса NFT")
            return False

        # ABI для функции balanceOf
        nft_abi = [
            {
                "inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function",
            }
        ]

        contract = w3.eth.contract(
            address=Web3.to_checksum_address(NFT_CONTRACT_ADDRESS), abi=nft_abi
        )

        balance = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()

        has_nft = balance > 0

        if has_nft:
            logger.info(
                f"Кошелек {address} уже имеет NFT Season 4 (баланс: {balance})"
            )
        else:
            logger.info(
                f"Кошелек {address} не имеет NFT Season 4 (баланс: {balance})"
            )

        return has_nft

    except Exception as e:
        logger.error(f"Ошибка при проверке баланса NFT для {address}: {e}")
        return False


# === Функции для работы с базой данных ===


def init_database(db_path: Path) -> None:
    """
    Создает базу данных и таблицы, если их нет.

    Args:
        db_path: Путь к файлу базы данных
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Создаем таблицу wallets
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS wallets (
                address TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                total_score INTEGER DEFAULT 0,
                claiming_period TEXT,
                last_check TIMESTAMP,
                mint_date TIMESTAMP,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Создаем индексы
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_wallets_status 
            ON wallets(status)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_wallets_last_check 
            ON wallets(last_check)
            """
        )

        conn.commit()
        conn.close()
        logger.debug(f"База данных инициализирована: {db_path}")

    except Exception as e:
        logger.error(f"Ошибка при инициализации базы данных: {e}")
        raise


def get_wallet_status(address: str, db_path: Path) -> Optional[dict]:
    """
    Получает статус кошелька из БД.

    Args:
        address: Адрес кошелька (checksum format)
        db_path: Путь к файлу базы данных

    Returns:
        Словарь с данными кошелька или None если не найден
    """
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT address, status, total_score, claiming_period, 
                   last_check, mint_date, error_message, updated_at
            FROM wallets
            WHERE address = ?
            """,
            (address,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "address": row["address"],
                "status": row["status"],
                "total_score": row["total_score"],
                "claiming_period": row["claiming_period"],
                "last_check": (
                    datetime.fromisoformat(row["last_check"])
                    if row["last_check"]
                    else None
                ),
                "mint_date": (
                    datetime.fromisoformat(row["mint_date"])
                    if row["mint_date"]
                    else None
                ),
                "error_message": row["error_message"],
                "updated_at": (
                    datetime.fromisoformat(row["updated_at"])
                    if row["updated_at"]
                    else None
                ),
            }

        return None

    except Exception as e:
        logger.error(f"Ошибка при получении статуса кошелька из БД: {e}")
        return None


def save_wallet_status(
    address: str,
    status: str,
    total_score: int = 0,
    claiming_period: Optional[str] = None,
    error_message: Optional[str] = None,
    mint_date: Optional[datetime] = None,
    db_path: Path = DB_PATH,
) -> None:
    """
    Сохраняет или обновляет статус кошелька в БД.

    Args:
        address: Адрес кошелька
        status: Статус ('minted', 'eligible', 'waiting', и т.д.)
        total_score: Количество поинтов
        claiming_period: Период клайма
        error_message: Сообщение об ошибке
        mint_date: Дата минтинга (если сминтили)
        db_path: Путь к файлу базы данных
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        now_utc = datetime.now(timezone.utc).isoformat()
        last_check_utc = now_utc
        mint_date_str = mint_date.isoformat() if mint_date else None

        cursor.execute(
            """
            INSERT OR REPLACE INTO wallets 
            (address, status, total_score, claiming_period, last_check, mint_date, error_message, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                address,
                status,
                total_score,
                claiming_period,
                last_check_utc,
                mint_date_str,
                error_message,
                now_utc,
            ),
        )

        conn.commit()
        conn.close()
        logger.debug(f"Статус кошелька {address} сохранен в БД: {status}")

    except Exception as e:
        logger.error(f"Ошибка при сохранении статуса кошелька в БД: {e}")


def should_check_wallet(
    address: str, db_path: Path
) -> tuple[bool, Optional[dict]]:
    """
    Определяет, нужно ли проверять кошелек заново.

    Логика:
    - Если статус 'minted' → не проверяем (return False) - уже сминтили
    - Если статус 'not_eligible' → не проверяем (return False) - не хватает поинтов
    - Если статус 'period_ended' → не проверяем (return False) - период закончился
    - Если статус 'waiting' → не проверяем (return False) - период еще не наступил (не изменится сам)
    - Если статус 'eligible' → проверяем (return True) - нужно минтить
    - Если статус 'no_data' или 'error' → проверяем (return True) - нужна повторная проверка
    - Если записи нет → проверяем (return True)

    Args:
        address: Адрес кошелька
        db_path: Путь к файлу базы данных

    Returns:
        (should_check, wallet_data)
        should_check: True если нужно проверить, False если пропустить
        wallet_data: Данные из БД или None
    """
    wallet_data = get_wallet_status(address, db_path)

    if not wallet_data:
        # Записи нет - нужно проверить
        return True, None

    status = wallet_data["status"]

    # Финальные статусы, которые не требуют повторной проверки
    if status in ("minted", "not_eligible", "period_ended", "waiting"):
        return False, wallet_data

    # Для остальных статусов ('eligible', 'no_data', 'error') - проверяем
    return True, wallet_data


def get_all_wallets(db_path: Path) -> list[dict]:
    """
    Получает все кошельки из базы данных.

    Args:
        db_path: Путь к файлу базы данных

    Returns:
        Список словарей с данными кошельков
    """
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT address, status, total_score, claiming_period, 
                   last_check, mint_date
            FROM wallets
            ORDER BY 
                CASE status
                    WHEN 'minted' THEN 1
                    WHEN 'eligible' THEN 2
                    WHEN 'waiting' THEN 3
                    WHEN 'not_eligible' THEN 4
                    WHEN 'period_ended' THEN 5
                    ELSE 6
                END,
                total_score DESC,
                address
            """
        )

        rows = cursor.fetchall()
        conn.close()

        wallets = []
        for row in rows:
            wallets.append(
                {
                    "address": row["address"],
                    "status": row["status"],
                    "total_score": row["total_score"],
                    "claiming_period": row["claiming_period"],
                    "last_check": (
                        datetime.fromisoformat(row["last_check"])
                        if row["last_check"]
                        else None
                    ),
                    "mint_date": (
                        datetime.fromisoformat(row["mint_date"])
                        if row["mint_date"]
                        else None
                    ),
                }
            )

        return wallets

    except Exception as e:
        logger.error(f"Ошибка при получении всех кошельков из БД: {e}")
        return []


def format_status_with_color(status: str) -> str:
    """
    Форматирует статус с цветом используя ANSI escape коды.

    Args:
        status: Статус кошелька

    Returns:
        Отформатированная строка со статусом и цветом
    """
    # ANSI escape коды для цветов
    color_map = {
        "minted": "\033[32m",  # зеленый
        "eligible": "\033[34m",  # синий
        "waiting": "\033[33m",  # желтый
        "not_eligible": "\033[31m",  # красный
        "period_ended": "\033[31m",  # красный
        "no_data": "\033[31m",  # красный
        "error": "\033[31m",  # красный
    }

    reset = "\033[0m"  # сброс цвета
    color_code = color_map.get(status, "\033[37m")  # белый по умолчанию

    return f"{color_code}{status}{reset}"


def print_wallets_table(wallets: list[dict]) -> None:
    """
    Выводит таблицу с данными всех кошельков с цветами через loguru.

    Args:
        wallets: Список словарей с данными кошельков
    """
    if not wallets:
        return

    logger.info("=" * 80)
    logger.info(" " * 20 + "СТАТИСТИКА ПО КОШЕЛЬКАМ")
    logger.info("=" * 80)

    # Заголовок таблицы
    header = f"{'Адрес':<42} | {'Статус':<15} | {'Поинты':<8} | {'Период клайма':<20}"
    logger.info(header)
    logger.info("-" * 80)

    # Данные кошельков
    for wallet in wallets:
        address = wallet["address"]
        status_colored = format_status_with_color(wallet["status"])
        total_score = wallet["total_score"] or 0
        claiming_period = wallet["claiming_period"] or "-"

        # Формируем строку с цветным статусом
        row = (
            f"{address:<42} | {status_colored:<15} | {total_score:<8} | {claiming_period:<20}"
        )
        logger.info(row)

    logger.info("=" * 80)


def get_database_stats(db_path: Path) -> dict:
    """
    Получает статистику из базы данных.

    Args:
        db_path: Путь к файлу базы данных

    Returns:
        Словарь со статистикой
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Общее количество
        cursor.execute("SELECT COUNT(*) FROM wallets")
        total = cursor.fetchone()[0]

        # По статусам
        cursor.execute(
            """
            SELECT status, COUNT(*) 
            FROM wallets 
            GROUP BY status
            """
        )
        status_counts = dict(cursor.fetchall())

        conn.close()

        return {
            "total": total,
            "minted": status_counts.get("minted", 0),
            "waiting": status_counts.get("waiting", 0),
            "not_eligible": status_counts.get("not_eligible", 0),
            "period_ended": status_counts.get("period_ended", 0),
            "no_data": status_counts.get("no_data", 0),
            "error": status_counts.get("error", 0),
        }

    except Exception as e:
        logger.error(f"Ошибка при получении статистики из БД: {e}")
        return {
            "total": 0,
            "minted": 0,
            "waiting": 0,
            "not_eligible": 0,
            "period_ended": 0,
            "no_data": 0,
            "error": 0,
        }


class Mint4Season:
    """
    Класс для создания и управления временными браузерами через AdsPower Local API.
    Создает временный профиль Windows, открывает браузер, импортирует кошелек,
    открывает страницу OpenSea для минтинга NFT Season 4, затем закрывает браузер
    и полностью удаляет профиль с кэшем.
    """

    def __init__(
        self,
        api_key: str,
        api_port: int = 50325,
        base_url: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Инициализация класса Mint4Season.

        Args:
            api_key: API ключ для AdsPower
            api_port: Порт API (по умолчанию 50325)
            base_url: Базовый URL API (если не указан, используется local.adspower.net)
            timeout: Таймаут для HTTP запросов в секундах
        """
        self.api_key = api_key
        self.api_port = api_port
        # Пробуем разные варианты базового URL
        if base_url:
            self.base_url = base_url
        else:
            # По умолчанию пробуем local.adspower.net, но можно использовать 127.0.0.1
            self.base_url = f"http://local.adspower.net:{api_port}"
        self.timeout = timeout
        self.profile_id: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        )
        # Время последнего запроса к API AdsPower (для rate limiting)
        self.last_request_time: float = 0.0
        # Минимальная задержка между запросами (в секундах)
        self.api_request_delay: float = 2.0

    async def _import_wallet_via_cdp(
        self, cdp_endpoint: str, private_key: str, password: str = "Password123"
    ) -> Optional[str]:
        """
        Импортирует кошелек Rabby через CDP endpoint.

        Args:
            cdp_endpoint: CDP endpoint (например, ws://127.0.0.1:9222)
            private_key: Приватный ключ для импорта
            password: Пароль для кошелька (по умолчанию Password123)

        Returns:
            Адрес импортированного кошелька или None, если не удалось извлечь
        """
        try:
            from playwright.async_api import async_playwright

            playwright = await async_playwright().start()
            try:
                browser = await playwright.chromium.connect_over_cdp(cdp_endpoint)

                if not browser.contexts:
                    logger.error("Не найдено контекстов в браузере (CDP)")
                    return None

                context = browser.contexts[0]

                # Ищем страницу с уже открытым расширением
                extension_id = RABBY_EXTENSION_ID
                setup_url = (
                    f"chrome-extension://{extension_id}/index.html#/new-user/guide"
                )

                page = None
                # Проверяем уже открытые страницы - ищем любую страницу расширения Rabby
                for existing_page in context.pages:
                    url = existing_page.url
                    # Проверяем, что это страница расширения Rabby
                    if extension_id in url or (
                        "chrome-extension://" in url and "rabby" in url.lower()
                    ):
                        page = existing_page
                        # Если это не страница настройки, переходим на неё
                        if "#/new-user/guide" not in url:
                            await page.goto(setup_url)
                            await asyncio.sleep(2)  # Даём время на загрузку
                        break

                # Если страница не найдена, открываем её
                if not page:
                    page = await context.new_page()
                    await page.goto(setup_url)
                    await asyncio.sleep(3)  # Даём время на загрузку

                # Шаг 1: Нажимаем "I already have an address"
                await page.wait_for_selector(
                    'span:has-text("I already have an address")', timeout=30000
                )
                await page.click('span:has-text("I already have an address")')

                # Шаг 2: Выбираем "Private Key"
                private_key_selector = 'div.rabby-ItemWrapper-rabby--mylnj7:has-text("Private Key")'
                await page.wait_for_selector(private_key_selector, timeout=30000)
                await page.click(private_key_selector)

                # Шаг 3: Вводим приватный ключ
                private_key_input = "#privateKey"
                await page.wait_for_selector(private_key_input, timeout=30000)
                await page.click(private_key_input)
                await page.fill(private_key_input, private_key)

                # Шаг 4: Подтверждаем импорт ключа
                confirm_button_selector = 'button:has-text("Confirm"):not([disabled])'
                await page.wait_for_selector(confirm_button_selector, timeout=30000)
                await page.click(confirm_button_selector)

                # Шаг 5: Вводим пароль
                password_input = "#password"
                await page.wait_for_selector(password_input, timeout=30000)
                await page.click(password_input)
                await page.fill(password_input, password)
                await page.press(password_input, "Tab")
                await page.keyboard.type(password)

                # Шаг 6: Подтверждаем установку пароля
                password_confirm_button = 'button:has-text("Confirm"):not([disabled])'
                await page.wait_for_selector(password_confirm_button, timeout=30000)
                await page.click(password_confirm_button)

                # Шаг 7: Ждём успешного импорта
                await page.wait_for_selector("text=Imported Successfully", timeout=30000)

                # Пытаемся извлечь адрес кошелька
                wallet_address = None
                try:
                    address = await page.evaluate(
                        """
                        () => {
                            const text = document.body.textContent;
                            const match = text.match(/0x[a-fA-F0-9]{40}/);
                            return match ? match[0] : null;
                        }
                    """
                    )
                    if address:
                        wallet_address = address
                except Exception:
                    pass

                return wallet_address

            finally:
                # В CDP-режиме не закрываем браузер/контекст — ими управляет AdsPower
                await playwright.stop()

        except Exception as e:
            logger.error(f"Ошибка при импорте кошелька: {e}")
            raise

    async def _open_opensea_and_mint_via_cdp(
        self, cdp_endpoint: str, wallet_address: Optional[str] = None
    ) -> bool:
        """
        Открывает OpenSea и выполняет минт NFT Season 4.

        Args:
            cdp_endpoint: CDP endpoint (например, ws://127.0.0.1:9222)
            wallet_address: Адрес кошелька для логирования (опционально)

        Returns:
            True если успешно открыли страницу и выполнили минт, False в случае ошибки
        """
        try:
            from playwright.async_api import async_playwright

            playwright = await async_playwright().start()
            try:
                browser = await playwright.chromium.connect_over_cdp(cdp_endpoint)

                if not browser.contexts:
                    logger.error("Не найдено контекстов в браузере (CDP)")
                    return False

                context = browser.contexts[0]

                # Закрываем все страницы расширения кошелька
                logger.info("Закрытие страниц расширения кошелька...")
                extension_pages = []
                for existing_page in context.pages:
                    if existing_page.url.startswith("chrome-extension://"):
                        extension_pages.append(existing_page)

                for ext_page in extension_pages:
                    try:
                        await ext_page.close()
                        logger.debug(f"Закрыта страница расширения: {ext_page.url}")
                    except Exception as e:
                        logger.debug(f"Ошибка при закрытии страницы расширения: {e}")

                if extension_pages:
                    logger.success(f"Закрыто страниц расширения: {len(extension_pages)}")
                    await asyncio.sleep(1)  # Небольшая задержка после закрытия

                # Открываем новую страницу или используем существующую не-расширение страницу
                page = None
                for existing_page in context.pages:
                    # Используем первую не-расширение страницу
                    if not existing_page.url.startswith("chrome-extension://"):
                        page = existing_page
                        break

                if not page:
                    page = await context.new_page()

                # Переходим на страницу OpenSea Season 4
                logger.info(f"Переход на страницу OpenSea: {OPENSEA_URL}")
                try:
                    await page.goto(OPENSEA_URL, wait_until="domcontentloaded", timeout=60000)
                except Exception as e:
                    logger.debug(f"domcontentloaded не завершился, пробуем load: {e}")
                    try:
                        await page.goto(OPENSEA_URL, wait_until="load", timeout=30000)
                    except Exception:
                        await page.goto(OPENSEA_URL, timeout=30000)

                await asyncio.sleep(5)  # Даём время на загрузку страницы

                # Нажимаем кнопку Mint
                logger.info("Нажимаю кнопку Mint...")
                mint_button_clicked = False
                try:
                    mint_selectors = [
                        'button:has-text("Mint")',
                        'button:has-text("Mint"):not([disabled])',
                        '[role="button"]:has-text("Mint")',
                    ]

                    for attempt in range(30):  # Пробуем до 30 раз с интервалом 1 сек
                        for selector in mint_selectors:
                            try:
                                mint_button = await page.query_selector(selector)
                                if mint_button:
                                    is_disabled = await mint_button.is_disabled()
                                    is_visible = await mint_button.is_visible()

                                    if not is_disabled and is_visible:
                                        await mint_button.click()
                                        logger.success("Кнопка Mint нажата")
                                        mint_button_clicked = True
                                        await asyncio.sleep(3)  # Даём время на открытие модального окна
                                        break
                            except Exception:
                                continue

                        if mint_button_clicked:
                            break

                        await asyncio.sleep(1)

                    if not mint_button_clicked:
                        logger.warning("Не удалось найти активную кнопку Mint за 30 секунд")
                        return False
                except Exception as e:
                    logger.warning(f"Ошибка при поиске/клике кнопки Mint: {e}")
                    return False

                # Ждем появления модального окна подключения кошелька
                await asyncio.sleep(3)

                # Выбираем Rabby Wallet в модальном окне
                logger.info("Выбираю Rabby Wallet в модальном окне...")
                rabby_wallet_clicked = False
                try:
                    rabby_selectors = [
                        'button:has-text("Rabby Wallet")',
                        'span:has-text("Rabby Wallet")',
                        'div:has-text("Rabby Wallet")',
                    ]

                    for attempt in range(10):  # Пробуем до 10 раз
                        for selector in rabby_selectors:
                            try:
                                rabby_element = await page.wait_for_selector(
                                    selector, timeout=2000
                                )
                                if rabby_element:
                                    await rabby_element.click()
                                    logger.success("Rabby Wallet выбран")
                                    rabby_wallet_clicked = True
                                    await asyncio.sleep(2)
                                    break
                            except Exception:
                                continue

                        if rabby_wallet_clicked:
                            break

                        await asyncio.sleep(1)

                    if not rabby_wallet_clicked:
                        logger.warning("Не удалось найти Rabby Wallet в модальном окне")
                        return False
                except Exception as e:
                    logger.warning(f"Ошибка при выборе Rabby Wallet: {e}")
                    return False

                # Ждем появления popup окна Rabby Wallet
                logger.info("Ожидаю появления popup окна Rabby Wallet...")
                rabby_popup_page: Optional[Any] = None

                for attempt in range(10):
                    for existing_page in context.pages:
                        url = existing_page.url
                        if (
                            "chrome-extension://" in url
                            and "/notification.html" in url
                        ):
                            rabby_popup_page = existing_page
                            logger.success("Найдено popup окно кошелька")
                            break

                    if rabby_popup_page:
                        break

                    await asyncio.sleep(2)

                if rabby_popup_page:
                    await rabby_popup_page.bring_to_front()

                    # Кликаем по кнопке "Connect" в popup
                    logger.info('Ищу кнопку "Connect" в popup...')
                    connect_clicked = False
                    try:
                        await rabby_popup_page.wait_for_selector(
                            'button:has-text("Connect")', timeout=10000
                        )
                        await rabby_popup_page.click('button:has-text("Connect")')
                        logger.success('Кликнул по кнопке "Connect" в popup')
                        connect_clicked = True
                        await asyncio.sleep(3)
                    except Exception as e:
                        logger.warning(
                            f'Не удалось найти кнопку Connect в popup окне: {e}'
                        )

                    if connect_clicked:
                        # Ждем появления нового popup окна для подписания
                        logger.info("Ожидаю появления popup окна для подписания...")
                        sign_popup_page: Optional[Any] = None

                        for attempt in range(10):
                            for existing_page in context.pages:
                                url = existing_page.url
                                if (
                                    "chrome-extension://" in url
                                    and "/notification.html" in url
                                ):
                                    sign_popup_page = existing_page
                                    logger.success("Найдено popup окно для подписания")
                                    break

                            if sign_popup_page:
                                break

                            await asyncio.sleep(2)

                        if sign_popup_page:
                            await sign_popup_page.bring_to_front()

                            # Кликаем по кнопке "Sign"
                            logger.info('Ищу кнопку "Sign"...')
                            sign_clicked = False
                            try:
                                await sign_popup_page.wait_for_selector(
                                    'button:has-text("Sign")', timeout=10000
                                )
                                await sign_popup_page.click('button:has-text("Sign")')
                                logger.success('Кликнул по кнопке "Sign"')
                                sign_clicked = True
                                await asyncio.sleep(2)
                            except Exception as e:
                                logger.warning(f'Не удалось найти кнопку "Sign": {e}')

                            if sign_clicked:
                                # Кликаем по кнопке "Confirm"
                                logger.info('Ищу кнопку "Confirm"...')
                                confirm_clicked = False
                                try:
                                    await sign_popup_page.wait_for_selector(
                                        'button:has-text("Confirm")', timeout=10000
                                    )
                                    await sign_popup_page.click('button:has-text("Confirm")')
                                    logger.success('Кликнул по кнопке "Confirm"')
                                    confirm_clicked = True
                                    await asyncio.sleep(3)
                                except Exception as e:
                                    logger.warning(
                                        f'Не удалось найти кнопку "Confirm": {e}'
                                    )

                                if confirm_clicked:
                                    # Ждем появления третьего popup окна для подписания транзакции клайма
                                    logger.info(
                                        "Ожидаю появления popup окна для подписания транзакции клайма..."
                                    )
                                    transaction_popup_page: Optional[Any] = None

                                    for attempt in range(15):
                                        for existing_page in context.pages:
                                            url = existing_page.url
                                            if (
                                                "chrome-extension://" in url
                                                and "/notification.html" in url
                                            ):
                                                transaction_popup_page = existing_page
                                                logger.success(
                                                    "Найдено popup окно для подписания транзакции"
                                                )
                                                break

                                        if transaction_popup_page:
                                            break

                                        await asyncio.sleep(2)

                                    if transaction_popup_page:
                                        await transaction_popup_page.bring_to_front()

                                        # Кликаем по кнопке "Sign" для транзакции
                                        logger.info(
                                            'Ищу кнопку "Sign" для транзакции...'
                                        )
                                        sign_tx_clicked = False
                                        try:
                                            await transaction_popup_page.wait_for_selector(
                                                'button:has-text("Sign")', timeout=15000
                                            )
                                            await transaction_popup_page.click(
                                                'button:has-text("Sign")'
                                            )
                                            logger.success(
                                                'Кликнул по кнопке "Sign" для транзакции'
                                            )
                                            sign_tx_clicked = True
                                            await asyncio.sleep(3)
                                        except Exception as e:
                                            logger.warning(
                                                f'Не удалось найти кнопку "Sign" для транзакции: {e}'
                                            )

                                        if sign_tx_clicked:
                                            # Кликаем по кнопке "Confirm" для транзакции
                                            logger.info(
                                                'Ищу кнопку "Confirm" для транзакции...'
                                            )
                                            try:
                                                await transaction_popup_page.wait_for_selector(
                                                    'button:has-text("Confirm")',
                                                    timeout=15000,
                                                )
                                                await transaction_popup_page.click(
                                                    'button:has-text("Confirm")'
                                                )
                                                logger.success(
                                                    'Кликнул по кнопке "Confirm" для транзакции'
                                                )

                                                # Ждем 5 секунд после подписания транзакции
                                                logger.info(
                                                    "Ожидаю 5 секунд после подписания транзакции..."
                                                )
                                                await asyncio.sleep(5)

                                                # Сообщение об успешном завершении клайма
                                                logger.success(
                                                    "Клайм NFT должен быть успешно выполнен!"
                                                )
                                                return True
                                            except Exception as e:
                                                logger.warning(
                                                    f'Не удалось найти кнопку "Confirm" для транзакции: {e}'
                                                )
                                    else:
                                        logger.warning(
                                            "Popup окно для подписания транзакции не найдено за 30 секунд"
                                        )
                else:
                    logger.warning("Popup окно Rabby Wallet не найдено за 20 секунд")

                logger.success("Страница OpenSea открыта успешно")
                return True

            finally:
                # В CDP-режиме не закрываем браузер/контекст — ими управляет AdsPower
                await playwright.stop()

        except Exception as e:
            logger.error(f"Ошибка при открытии OpenSea: {e}")
            return False

    def _make_request(
        self, method: str, endpoint: str, data: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Выполняет HTTP запрос к AdsPower API.
        Пробует разные способы передачи API ключа и форматы эндпоинтов.

        Args:
            method: HTTP метод (GET, POST, DELETE)
            endpoint: Эндпоинт API
            data: Данные для отправки (для POST/DELETE)

        Returns:
            Ответ API в виде словаря

        Raises:
            requests.RequestException: При ошибке HTTP запроса
            ValueError: При ошибке в ответе API
        """
        # Пробуем разные варианты эндпоинтов
        if "/api/v2/" in endpoint:
            endpoints_to_try = [endpoint]
        else:
            endpoints_to_try = [
                endpoint.replace("/api/v1/", "/api/v2/"),
                endpoint,
                endpoint.replace("/api/v1/", "/v1/"),
                endpoint.replace("/api/v1/", "/api/"),
            ]

        endpoints_to_try = list(dict.fromkeys(endpoints_to_try))

        # Добавляем задержку между запросами к API AdsPower для избежания rate limit
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.api_request_delay:
            sleep_time = self.api_request_delay - time_since_last_request
            logger.debug(
                f"Задержка {sleep_time:.2f} сек перед запросом к API AdsPower (rate limiting)"
            )
            time.sleep(sleep_time)

        last_error = None
        request_made = False

        for endpoint_variant in endpoints_to_try:
            url = f"{self.base_url}{endpoint_variant}"
            params = {"api_key": self.api_key}

            try:
                if method.upper() == "GET":
                    response = self.session.get(url, params=params, timeout=self.timeout)
                elif method.upper() == "POST":
                    logger.debug(f"POST запрос к {url} с данными: {data}")
                    response = self.session.post(
                        url, params=params, json=data, timeout=self.timeout
                    )
                    logger.debug(
                        f"Ответ: статус {response.status_code}, тело: {response.text[:200]}"
                    )
                elif method.upper() == "DELETE":
                    response = self.session.delete(
                        url, params=params, json=data, timeout=self.timeout
                    )
                else:
                    raise ValueError(f"Неподдерживаемый HTTP метод: {method}")

                request_made = True
                self.last_request_time = time.time()

                if response.status_code == 404:
                    last_error = f"404 Not Found: {url}"
                    logger.debug(
                        f"Эндпоинт {endpoint_variant} вернул 404, пробуем следующий вариант"
                    )
                    continue

                response.raise_for_status()
                result = response.json()

                if result.get("code") != 0:
                    error_msg = result.get("msg", "Неизвестная ошибка API")
                    raise ValueError(f"Ошибка API: {error_msg}")

                logger.debug(f"Успешный запрос к {endpoint_variant}")
                return result

            except requests.RequestException as e:
                last_error = str(e)
                if not request_made:
                    request_made = True
                    self.last_request_time = time.time()

                if hasattr(e, "response") and e.response is not None:
                    if e.response.status_code == 404:
                        logger.debug(
                            f"Эндпоинт {endpoint_variant} вернул 404, пробуем следующий вариант"
                        )
                        continue
                logger.debug(
                    f"Ошибка для {endpoint_variant}: {e}, пробуем следующий вариант"
                )
                continue
            except ValueError as e:
                raise

        raise requests.RequestException(
            f"Все варианты эндпоинтов вернули ошибку. Последняя ошибка: {last_error}"
        )

    def create_temp_profile(self, name: Optional[str] = None, use_proxy: bool = True) -> str:
        """
        Создает временный профиль Windows используя API v2.

        Args:
            name: Имя профиля (если не указано, генерируется автоматически)
            use_proxy: Использовать ли случайный прокси (по умолчанию True)

        Returns:
            ID созданного профиля
        """
        if name is None:
            timestamp = int(time.time())
            unique_id = str(uuid.uuid4())[:8]
            name = f"temp_windows_{timestamp}_{unique_id}"

        logger.info(f"Создание временного профиля Windows: {name}")

        profile_data = {
            "name": name,
            "group_id": "0",
            "fingerprint_config": {
                "automatic_timezone": "1",
                "language": ["en-US", "en"],
                "webrtc": "disabled",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        }

        if use_proxy:
            profile_data["proxyid"] = "random"
            logger.info("Использование случайного прокси из сохраненных")
        else:
            profile_data["user_proxy_config"] = {"proxy_soft": "no_proxy"}
            logger.info("Профиль создается без прокси")

        try:
            result = self._make_request("POST", "/api/v2/browser-profile/create", profile_data)
            self.profile_id = result.get("data", {}).get("profile_id")
            if not self.profile_id:
                raise ValueError("API не вернул profile_id профиля")

            logger.success(f"Профиль создан успешно. ID: {self.profile_id}")
            return self.profile_id

        except Exception as e:
            logger.error(f"Ошибка при создании профиля: {e}")
            raise

    def start_browser(self, profile_id: Optional[str] = None) -> dict[str, Any]:
        """
        Запускает браузер с указанным профилем используя API v2.

        Args:
            profile_id: ID профиля (если не указан, используется последний созданный)

        Returns:
            Данные о запущенном браузере
        """
        profile_id_value = profile_id or self.profile_id
        if not profile_id_value:
            raise ValueError("Не указан profile_id и нет созданного профиля")

        logger.info(f"Запуск браузера для профиля {profile_id_value}")

        browser_data = {"profile_id": profile_id_value}

        try:
            result = self._make_request("POST", "/api/v2/browser-profile/start", browser_data)
            browser_info = result.get("data", {})

            if not browser_info:
                raise ValueError("API не вернул данные о браузере")

            logger.success(f"Браузер запущен успешно")
            logger.debug(f"Информация о браузере: {browser_info}")

            return browser_info

        except Exception as e:
            logger.error(f"Ошибка при запуске браузера: {e}")
            raise

    def stop_browser(self, profile_id: Optional[str] = None) -> bool:
        """
        Останавливает браузер для указанного профиля используя API v2.

        Args:
            profile_id: ID профиля (если не указан, используется последний созданный)

        Returns:
            True если браузер успешно остановлен
        """
        profile_id_value = profile_id or self.profile_id
        if not profile_id_value:
            logger.warning("Не указан profile_id для остановки браузера")
            return False

        logger.info(f"Остановка браузера для профиля {profile_id_value}")

        browser_data = {"profile_id": profile_id_value}

        try:
            self._make_request("POST", "/api/v2/browser-profile/stop", browser_data)
            logger.success(f"Браузер остановлен успешно")
            return True

        except Exception as e:
            logger.error(f"Ошибка при остановке браузера: {e}")
            return False

    def delete_cache(self, profile_id: Optional[str] = None) -> bool:
        """
        Очищает кэш профиля используя API v2.

        Args:
            profile_id: ID профиля (если не указан, используется последний созданный)

        Returns:
            True если кэш успешно очищен
        """
        profile_id_value = profile_id or self.profile_id
        if not profile_id_value:
            logger.warning("Не указан profile_id для очистки кэша")
            return False

        logger.info(f"Очистка кэша профиля {profile_id_value}")

        cache_data = {
            "profile_id": [profile_id_value],
            "type": [
                "local_storage",
                "indexeddb",
                "extension_cache",
                "cookie",
                "history",
                "image_file",
            ],
        }

        try:
            self._make_request("POST", "/api/v2/browser-profile/delete-cache", cache_data)
            logger.success(f"Кэш профиля {profile_id_value} очищен успешно")
            return True

        except Exception as e:
            logger.error(f"Ошибка при очистке кэша: {e}")
            return False

    def delete_profile(self, profile_id: Optional[str] = None, clear_cache: bool = True) -> bool:
        """
        Удаляет профиль используя API v2.

        Args:
            profile_id: ID профиля (если не указан, используется последний созданный)
            clear_cache: Очистить кэш перед удалением (по умолчанию True)

        Returns:
            True если профиль успешно удален
        """
        profile_id_value = profile_id or self.profile_id
        if not profile_id_value:
            logger.warning("Не указан profile_id для удаления профиля")
            return False

        if clear_cache:
            self.delete_cache(profile_id_value)

        logger.info(f"Удаление профиля {profile_id_value}")

        delete_data_variants = [
            {"profile_id": [profile_id_value]},
            {"Profile_id": [profile_id_value]},
        ]

        for delete_data in delete_data_variants:
            try:
                logger.debug(f"Пробуем удалить профиль с параметром: {list(delete_data.keys())[0]}")
                self._make_request("POST", "/api/v2/browser-profile/delete", delete_data)
                logger.success(f"Профиль {profile_id_value} удален успешно")
                self.profile_id = None
                return True
            except ValueError as e:
                error_msg = str(e)
                if "profile_id" in error_msg.lower() or "Profile_id" in error_msg:
                    logger.debug(
                        f"Вариант {list(delete_data.keys())[0]} не сработал: {e}, пробуем следующий"
                    )
                    continue
                raise
            except Exception as e:
                logger.error(f"Ошибка при удалении профиля: {e}")
                return False

        logger.error(f"Не удалось удалить профиль {profile_id_value} ни с одним вариантом параметра")
        return False

    def run_full_cycle(
        self,
        wait_time: int = 3,
        import_wallet: bool = True,
        key_index: int = 0,
        wallet_password: str = "Password123",
        use_proxy: bool = True,
        check_progress: bool = True,
    ) -> bool:
        """
        Выполняет полный цикл: создание профиля -> открытие браузера -> импорт кошелька ->
        открытие страницы OpenSea -> минт NFT -> закрытие -> удаление.

        Args:
            wait_time: Время ожидания в секундах (по умолчанию 3)
            import_wallet: Импортировать ли кошелек Rabby (по умолчанию True)
            key_index: Индекс приватного ключа из keys.txt (по умолчанию 0)
            wallet_password: Пароль для кошелька (по умолчанию Password123)
            use_proxy: Использовать ли случайный прокси (по умолчанию True)
            check_progress: Проверять ли прогресс перед выполнением (по умолчанию True)

        Returns:
            True если цикл выполнен, False если кошелек уже имеет NFT или не eligible
        """
        try:
            # Проверяем прогресс перед выполнением (если включено)
            if check_progress:
                try:
                    private_key = load_private_key(key_index=key_index)
                    wallet_address = Web3.to_checksum_address(
                        Web3().eth.account.from_key(private_key).address
                    )

                    # Проверка наличия NFT
                    has_nft = check_nft_balance(wallet_address)
                    if has_nft:
                        logger.info(f"[SKIP] {wallet_address} already has NFT Season 4")
                        return False

                    # Проверка eligibility
                    eligibility_result = check_season4_eligibility(wallet_address)
                    if eligibility_result["status"] != "eligible":
                        logger.info(
                            f"[SKIP] {wallet_address} not eligible: {eligibility_result['message']}"
                        )
                        return False

                except Exception as e:
                    logger.warning(f"Ошибка при проверке прогресса: {e}, продолжаем выполнение...")

            # 1. Создание временного профиля Windows
            profile_id = self.create_temp_profile(use_proxy=use_proxy)

            # 2. Запуск браузера
            browser_info = self.start_browser(profile_id)

            # 3. Импорт кошелька (если включен)
            if import_wallet:
                try:
                    cdp_endpoint = None
                    ws_data = browser_info.get("ws")
                    if isinstance(ws_data, dict):
                        cdp_endpoint = ws_data.get("puppeteer")

                    if not cdp_endpoint:
                        cdp_endpoint = (
                            browser_info.get("ws_endpoint")
                            or browser_info.get("ws_endpoint_driver")
                            or browser_info.get("puppeteer")
                            or browser_info.get("debugger_address")
                        )

                        if isinstance(cdp_endpoint, dict):
                            cdp_endpoint = cdp_endpoint.get("puppeteer") or cdp_endpoint.get("ws")

                    if not cdp_endpoint:
                        for key, value in browser_info.items():
                            if isinstance(value, str) and value.startswith("ws://"):
                                cdp_endpoint = value
                                break
                            elif isinstance(value, dict):
                                cdp_endpoint = value.get("puppeteer") or value.get("ws")
                                if cdp_endpoint:
                                    break

                    if cdp_endpoint and isinstance(cdp_endpoint, str):
                        private_key = load_private_key(key_index=key_index)
                        wallet_address = Web3.to_checksum_address(
                            Web3().eth.account.from_key(private_key).address
                        )
                        logger.info(f"Адрес кошелька: {wallet_address}")

                        time.sleep(5)

                        wallet_address_imported = asyncio.run(
                            self._import_wallet_via_cdp(
                                cdp_endpoint=cdp_endpoint,
                                private_key=private_key,
                                password=wallet_password,
                            )
                        )
                        logger.success("Импорт кошелька завершён")

                        # Открываем страницу OpenSea и выполняем минт
                        logger.info("Открытие страницы OpenSea...")
                        opensea_result = asyncio.run(
                            self._open_opensea_and_mint_via_cdp(
                                cdp_endpoint=cdp_endpoint, wallet_address=wallet_address
                            )
                        )
                        if opensea_result:
                            logger.success("Минт NFT выполнен успешно")
                        else:
                            logger.warning("Не удалось выполнить минт, но продолжаем выполнение цикла")
                    else:
                        logger.warning(
                            f"CDP endpoint не найден в browser_info. "
                            f"Импорт кошелька пропущен."
                        )
                except Exception as e:
                    logger.error(f"Ошибка при импорте кошелька: {e}")
                    logger.warning("Продолжаем выполнение цикла без импорта кошелька")

            # 4. Ожидание указанное время
            logger.info(f"Ожидание {wait_time} секунд...")
            time.sleep(wait_time)

            # 5. Остановка браузера
            self.stop_browser(profile_id)

            # 6. Удаление профиля с полной очисткой кэша
            self.delete_profile(profile_id, clear_cache=True)

            logger.success("Полный цикл выполнен успешно")
            return True

        except KeyboardInterrupt:
            logger.warning("Прервано пользователем")
            if self.profile_id:
                try:
                    self.stop_browser(self.profile_id)
                    self.delete_profile(self.profile_id, clear_cache=True)
                except Exception:
                    pass
            return False
        except Exception as e:
            logger.error(f"Ошибка при выполнении цикла: {e}")
            if self.profile_id:
                try:
                    self.stop_browser(self.profile_id)
                    self.delete_profile(self.profile_id, clear_cache=True)
                except Exception:
                    pass
            return True


def run() -> None:
    """
    Главная функция для запуска модуля из main.py.
    Загружает API ключ из файла и выполняет полный цикл для всех ключей в случайном порядке.
    Продолжает выполнение пока все кошельки не получат NFT или не будут обработаны.
    """
    import random

    # Настройка логирования
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        level="INFO",
    )

    try:
        # Инициализация базы данных
        init_database(DB_PATH)
        logger.info(f"База данных инициализирована: {DB_PATH}")

        # Выводим статистику из БД
        stats = get_database_stats(DB_PATH)
        if stats["total"] > 0:
            logger.info(
                f"Статистика БД: всего={stats['total']}, "
                f"minted={stats['minted']}, waiting={stats['waiting']}, "
                f"not_eligible={stats['not_eligible']}"
            )

        # Загрузка API ключа из файла
        api_key = load_adspower_api_key()
        logger.info("API ключ загружен из файла")

        # Загрузка всех ключей из keys.txt
        all_keys = load_all_keys()
        logger.info(f"Загружено ключей из keys.txt: {len(all_keys)}")

        # Создание экземпляра
        browser_manager = Mint4Season(api_key=api_key)

        iteration = 0

        # Основной цикл: продолжаем пока есть кошельки, которым нужен минт
        while True:
            iteration += 1
            logger.info("[ITERATION] starting iteration #{}", iteration)
            print(f"\n=== Итерация #{iteration} ===")

            # Создаем список индексов и перемешиваем их случайно на каждой итерации
            indices = list(range(len(all_keys)))
            random.shuffle(indices)

            wallets_need_progress = 0
            wallets_completed = 0

            # Обрабатываем каждый кошелек
            for i in indices:
                key_index = i
                key_num = i + 1

                logger.info(f"=" * 60)
                logger.info(
                    f"Обработка ключа {key_num}/{len(all_keys)} (индекс в файле: {key_index})"
                )
                logger.info(f"=" * 60)

                try:
                    # Проверяем прогресс перед выполнением
                    try:
                        private_key = load_private_key(key_index=key_index)
                        wallet_address = Web3.to_checksum_address(
                            Web3().eth.account.from_key(private_key).address
                        )

                        # 0. Проверяем БД перед проверкой через API
                        should_check, wallet_data = should_check_wallet(
                            wallet_address, DB_PATH
                        )

                        if not should_check:
                            # Пропускаем кошелек на основе данных из БД
                            if wallet_data:
                                status = wallet_data["status"]
                                if status == "minted":
                                    logger.info(
                                        f"[SKIP DB] {wallet_address} already minted (from DB)"
                                    )
                                elif status in ("not_eligible", "period_ended", "waiting"):
                                    logger.info(
                                        f"[SKIP DB] {wallet_address} {status} (from DB)"
                                    )
                            wallets_completed += 1
                            continue

                        # 1. Проверка наличия NFT Season 4
                        has_nft = check_nft_balance(wallet_address)
                        if has_nft:
                            # Получаем данные eligibility для сохранения полной информации
                            eligibility_result = check_season4_eligibility(wallet_address)
                            
                            # Сохраняем в БД статус 'minted' с данными eligibility
                            save_wallet_status(
                                wallet_address,
                                status="minted",
                                total_score=eligibility_result.get("totalScore", 0),
                                claiming_period=eligibility_result.get("claimingPeriod"),
                                db_path=DB_PATH,
                                mint_date=datetime.now(timezone.utc),
                            )
                            logger.info(
                                f"[SKIP] {wallet_address} already has NFT Season 4"
                            )
                            wallets_completed += 1
                            continue

                        # 2. Проверка eligibility для Season 4
                        eligibility_result = check_season4_eligibility(wallet_address)

                        # Сохраняем результат в БД
                        save_wallet_status(
                            wallet_address,
                            status=eligibility_result["status"],
                            total_score=eligibility_result.get("totalScore", 0),
                            claiming_period=eligibility_result.get("claimingPeriod"),
                            error_message=eligibility_result.get("error"),
                            db_path=DB_PATH,
                        )

                        if eligibility_result["status"] == "eligible":
                            logger.info(
                                f"{wallet_address} eligible for claim! {eligibility_result['message']}"
                            )
                            if eligibility_result.get("claimingPeriod"):
                                logger.info(
                                    f"Claiming period: {eligibility_result['claimingPeriod']}"
                                )
                            logger.info(
                                f"Season 4 Score: {eligibility_result['totalScore']} points"
                            )

                            # Выполняем минт
                            cycle_result = browser_manager.run_full_cycle(
                                wait_time=3,
                                key_index=key_index,
                                check_progress=False,  # Уже проверили выше
                            )

                            if cycle_result:
                                # После успешного минтинга обновляем статус на 'minted'
                                save_wallet_status(
                                    wallet_address,
                                    status="minted",
                                    total_score=eligibility_result.get("totalScore", 0),
                                    claiming_period=eligibility_result.get(
                                        "claimingPeriod"
                                    ),
                                    db_path=DB_PATH,
                                    mint_date=datetime.now(timezone.utc),
                                )
                                wallets_need_progress += 1
                                logger.success(
                                    f"Ключ {key_num}/{len(all_keys)} обработан успешно"
                                )
                            else:
                                wallets_completed += 1
                                logger.info(
                                    f"Ключ {key_num}/{len(all_keys)} уже выполнен, пропущен"
                                )

                        elif eligibility_result["status"] == "waiting":
                            logger.info(
                                f"{wallet_address} waiting for claiming period: {eligibility_result.get('claimingPeriod', 'N/A')}"
                            )
                            wallets_completed += 1
                            continue

                        elif eligibility_result["status"] == "period_ended":
                            logger.info(
                                f"{wallet_address} claiming period ended: {eligibility_result.get('claimingPeriod', 'N/A')}"
                            )
                            wallets_completed += 1
                            continue

                        elif eligibility_result["status"] == "not_eligible":
                            logger.info(
                                f"{wallet_address} not eligible: {eligibility_result['message']}"
                            )
                            if eligibility_result.get("totalScore", 0) > 0:
                                logger.info(
                                    f"Season 4 Score: {eligibility_result['totalScore']} points (minimum: {SEASON4_MIN_SCORE})"
                                )
                            wallets_completed += 1
                            continue

                        elif eligibility_result["status"] == "no_data":
                            logger.warning(
                                f"{wallet_address} no data available: {eligibility_result.get('error', 'Unknown error')}"
                            )
                            wallets_need_progress += 1
                            continue

                    except Exception as e:
                        logger.error(f"Ошибка при обработке ключа {key_num}/{len(all_keys)}: {e}")
                        wallets_need_progress += 1
                        continue

                    # Небольшая задержка между обработкой разных ключей
                    if i < len(indices) - 1:
                        delay = random.randint(5, 15)
                        logger.info(
                            f"Ожидание {delay} секунд перед обработкой следующего ключа..."
                        )
                        time.sleep(delay)

                except Exception as e:
                    logger.error(f"Ошибка при обработке ключа {key_num}/{len(all_keys)}: {e}")
                    wallets_need_progress += 1
                    continue

            # Если все кошельки достигли цели - завершаем
            if wallets_need_progress == 0:
                logger.info("[COMPLETE] all wallets processed")
                
                # Выводим финальную статистику из БД
                final_stats = get_database_stats(DB_PATH)
                if final_stats["total"] > 0:
                    logger.info(
                        f"Статистика БД: всего={final_stats['total']}, "
                        f"minted={final_stats['minted']}, waiting={final_stats['waiting']}, "
                        f"not_eligible={final_stats['not_eligible']}"
                    )
                    
                    # Выводим таблицу со всеми кошельками
                    all_wallets = get_all_wallets(DB_PATH)
                    if all_wallets:
                        logger.info("")  # Пустая строка для разделения
                        print_wallets_table(all_wallets)
                
                print(f"\nВсе кошельки обработаны!")
                break

            # Логируем статистику итерации
            logger.info(
                "[ITERATION] #{} completed: {} wallets need progress, {} wallets completed",
                iteration,
                wallets_need_progress,
                wallets_completed,
            )
            print(
                f"Итерация #{iteration} завершена: {wallets_need_progress} кошельков нуждаются в прогрессе, {wallets_completed} завершены"
            )

    except FileNotFoundError as e:
        logger.error(f"{e}")
        raise SystemExit(1)
    except ValueError as e:
        logger.error(f"{e}")
        raise SystemExit(1)
    except Exception as e:
        logger.error(f"Ошибка при выполнении: {e}")
        raise


if __name__ == "__main__":
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        level="INFO",
    )
    run()

