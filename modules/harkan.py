#!/usr/bin/env python3
from __future__ import annotations

import random
import re
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import requests
from loguru import logger
from web3 import Web3

# Позволяет запускать файл напрямую: `python modules/harkan.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    root_s = str(PROJECT_ROOT)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)

# Импорт функций для работы с БД
try:
    from modules.db_utils import (
        init_quests_database,
        is_wallet_completed,
        mark_wallet_completed,
        QUESTS_DB_PATH,
        init_harkan_accounts_table,
        get_harkan_account,
        save_harkan_account,
        update_harkan_claim,
        is_harkan_claim_requested,
    )
except ImportError:
    # Fallback если модуль не найден
    def init_quests_database(*args, **kwargs):
        pass

    def is_wallet_completed(*args, **kwargs):
        return False

    def mark_wallet_completed(*args, **kwargs):
        pass

    QUESTS_DB_PATH = PROJECT_ROOT / "quests.db"

    def init_harkan_accounts_table(*args, **kwargs):
        pass

    def get_harkan_account(*args, **kwargs):
        return None

    def save_harkan_account(*args, **kwargs):
        pass

    def update_harkan_claim(*args, **kwargs):
        pass

    def is_harkan_claim_requested(*args, **kwargs):
        return False

# ==================== КОНФИГУРАЦИЯ ====================
# Конфиг RPC для Soneium
RPC_URL_DEFAULT = "https://soneium-rpc.publicnode.com"
CHAIN_ID = 1868

# Адрес контракта NFT Harkan
HARKAN_NFT_CONTRACT = "0x6ef4a1aa389c805536ceaedd482e57db205413a6"

# API Harkan
HARKAN_API_BASE = "https://www.harkan.io/api"
HARKAN_REGISTER_URL = f"{HARKAN_API_BASE}/auth/register"
HARKAN_LOGIN_URL = f"{HARKAN_API_BASE}/auth/login"
HARKAN_ME_URL = f"{HARKAN_API_BASE}/auth/me"
HARKAN_CLAIM_URL = f"{HARKAN_API_BASE}/badges/claim"

# Badge ID для клайма и проверки баланса (ERC-1155 token ID)
BADGE_ID = 1

# Файл с прокси
PROXY_FILE = PROJECT_ROOT / "proxy.txt"

# Константы для задержек между действиями
DELAY_AFTER_REGISTER_MIN_SEC = 5   # После регистрации → перед логином
DELAY_AFTER_REGISTER_MAX_SEC = 15
DELAY_AFTER_LOGIN_MIN_SEC = 5      # После логина → перед получением данных
DELAY_AFTER_LOGIN_MAX_SEC = 15
DELAY_AFTER_ACCOUNT_INFO_MIN_SEC = 15  # После получения данных → перед заявкой
DELAY_AFTER_ACCOUNT_INFO_MAX_SEC = 30
DELAY_BETWEEN_USERNAME_ATTEMPTS_MIN_SEC = 5  # Между попытками регистрации
DELAY_BETWEEN_USERNAME_ATTEMPTS_MAX_SEC = 15

# Константы для задержки между кошельками (как в metamap.py)
MIN_DELAY_MINUTES = 1   # Минимальная задержка: 1 минута
MAX_DELAY_MINUTES = 100 # Максимальная задержка: 100 минут
DEFAULT_DELAY_MIN_MINUTES = 5  # Значение по умолчанию (минимум)
DEFAULT_DELAY_MAX_MINUTES = 10  # Значение по умолчанию (максимум)

# ==================== ФУНКЦИИ ЗАГРУЗКИ ====================


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


def validate_proxy_count(keys_count: int, proxies_count: int) -> None:
    """
    Проверяет, что прокси достаточно для всех кошельков.
    Строго: 1 аккаунт = 1 прокси.

    Args:
        keys_count: Количество кошельков
        proxies_count: Количество прокси

    Raises:
        RuntimeError: Если прокси недостаточно
    """
    if proxies_count < keys_count:
        raise RuntimeError(
            f"Недостаточно прокси! Кошельков: {keys_count}, прокси: {proxies_count}. "
            "Требуется минимум {keys_count} прокси (строго 1 аккаунт = 1 прокси)."
        )


def assign_proxy_to_wallet(wallet_index: int, proxies_list: list[ProxyEntry]) -> ProxyEntry:
    """
    Назначает прокси кошельку по индексу.

    Args:
        wallet_index: Индекс кошелька
        proxies_list: Список доступных прокси

    Returns:
        ProxyEntry объект
    """
    if wallet_index >= len(proxies_list):
        raise RuntimeError(
            f"Индекс кошелька {wallet_index} вне диапазона прокси (доступно: {len(proxies_list)})"
        )
    return proxies_list[wallet_index]


# ==================== ФУНКЦИИ ЗАДЕРЖЕК ====================


def random_delay(min_seconds: float, max_seconds: float, reason: str = "") -> None:
    """
    Выполняет случайную задержку с Gaussian распределением для более естественного поведения.

    Args:
        min_seconds: Минимальная задержка в секундах
        max_seconds: Максимальная задержка в секундах
        reason: Причина задержки (для логирования, опционально)
    """
    # Вычисляем среднее и стандартное отклонение для Gaussian распределения
    mean = (min_seconds + max_seconds) / 2
    std_dev = (max_seconds - min_seconds) / 4  # ~95% значений в диапазоне

    # Генерируем задержку с Gaussian распределением
    delay = random.gauss(mean, std_dev)

    # Ограничиваем значения диапазоном [min_seconds, max_seconds]
    delay = max(min_seconds, min(max_seconds, delay))

    # Округляем до 1 знака после запятой
    delay = round(delay, 1)

    if reason:
        logger.info(f"[DELAY] {reason}: {delay} секунд")

    time.sleep(delay)


def random_delay_minutes(min_minutes: float, max_minutes: float, reason: str = "") -> None:
    """
    Выполняет случайную задержку в минутах с Gaussian распределением.

    Args:
        min_minutes: Минимальная задержка в минутах
        max_minutes: Максимальная задержка в минутах
        reason: Причина задержки (для логирования, опционально)
    """
    # Конвертируем минуты в секунды и используем random_delay()
    min_seconds = min_minutes * 60
    max_seconds = max_minutes * 60
    
    # Вычисляем среднее и стандартное отклонение для Gaussian распределения
    mean = (min_seconds + max_seconds) / 2
    std_dev = (max_seconds - min_seconds) / 4  # ~95% значений в диапазоне

    # Генерируем задержку с Gaussian распределением
    delay_seconds = random.gauss(mean, std_dev)

    # Ограничиваем значения диапазоном [min_seconds, max_seconds]
    delay_seconds = max(min_seconds, min(max_seconds, delay_seconds))

    # Округляем до 1 знака после запятой
    delay_seconds = round(delay_seconds, 1)
    delay_minutes = round(delay_seconds / 60, 2)

    if reason:
        logger.info(f"[DELAY] {reason}: {delay_minutes} минут ({delay_seconds} секунд)")

    time.sleep(delay_seconds)


def get_delay_minutes_from_user() -> tuple[int, int]:
    """
    Запрашивает у пользователя диапазон задержки в минутах (целое число от 1 до 100).
    Задержка будет случайной в указанном диапазоне.

    Returns:
        Кортеж (min_minutes, max_minutes)
    """
    print("\n" + "=" * 60)
    print("Настройка задержки между обработкой кошельков")
    print("=" * 60)
    print(f"Укажите задержку в МИНУТАХ (целое число от {MIN_DELAY_MINUTES} до {MAX_DELAY_MINUTES})")
    print("Задержка будет случайной в указанном диапазоне")
    print("=" * 60)

    while True:
        try:
            min_input = input(f"Минимальная задержка (минуты, {MIN_DELAY_MINUTES}-{MAX_DELAY_MINUTES}): ").strip()

            if not min_input:
                print("❌ Введите число. Попробуйте снова.")
                continue

            min_minutes = int(min_input)

            if min_minutes < MIN_DELAY_MINUTES:
                print(f"❌ Минимальная задержка: {MIN_DELAY_MINUTES} минута. Попробуйте снова.")
                continue

            if min_minutes > MAX_DELAY_MINUTES:
                print(f"❌ Максимальная задержка: {MAX_DELAY_MINUTES} минут. Попробуйте снова.")
                continue

            break

        except ValueError:
            print("❌ Неверный формат. Введите целое число (например: 5).")
            continue
        except (KeyboardInterrupt, EOFError):
            # Если пользователь прервал ввод - используем значение по умолчанию
            print(f"\nИспользуется значение по умолчанию: {DEFAULT_DELAY_MIN_MINUTES}-{DEFAULT_DELAY_MAX_MINUTES} минут")
            return (DEFAULT_DELAY_MIN_MINUTES, DEFAULT_DELAY_MAX_MINUTES)

    while True:
        try:
            max_input = input(f"Максимальная задержка (минуты, {MIN_DELAY_MINUTES}-{MAX_DELAY_MINUTES}): ").strip()

            if not max_input:
                print("❌ Введите число. Попробуйте снова.")
                continue

            max_minutes = int(max_input)

            if max_minutes < MIN_DELAY_MINUTES:
                print(f"❌ Минимальная задержка: {MIN_DELAY_MINUTES} минута. Попробуйте снова.")
                continue

            if max_minutes > MAX_DELAY_MINUTES:
                print(f"❌ Максимальная задержка: {MAX_DELAY_MINUTES} минут. Попробуйте снова.")
                continue

            if max_minutes < min_minutes:
                print(f"❌ Максимальная задержка ({max_minutes}) не может быть меньше минимальной ({min_minutes}). Попробуйте снова.")
                continue

            return (min_minutes, max_minutes)

        except ValueError:
            print("❌ Неверный формат. Введите целое число (например: 15).")
            continue
        except (KeyboardInterrupt, EOFError):
            # Если пользователь прервал ввод - используем значение по умолчанию
            print(f"\nИспользуется значение по умолчанию: {DEFAULT_DELAY_MIN_MINUTES}-{DEFAULT_DELAY_MAX_MINUTES} минут")
            return (DEFAULT_DELAY_MIN_MINUTES, DEFAULT_DELAY_MAX_MINUTES)


# ==================== ФУНКЦИИ ГЕНЕРАЦИИ ====================


def _generate_username_fallback() -> str:
    """
    Fallback генератор username (если Faker недоступен).

    Returns:
        Случайный username
    """
    # Используем буквы и цифры, исключая слово "harkan"
    chars = string.ascii_lowercase + string.digits
    # Генерируем случайную длину от 8 до 16 символов
    length = random.randint(8, 16)
    username = "".join(random.choice(chars) for _ in range(length))
    # Убеждаемся, что username не содержит "harkan" (в любом регистре)
    while "harkan" in username.lower():
        username = "".join(random.choice(chars) for _ in range(length))
    return username


def generate_username() -> str:
    """
    Генерирует реалистичный username через Faker.

    Returns:
        Реалистичный username без слова "harkan"
    """
    try:
        from faker import Faker
        fake = Faker()

        max_attempts = 10
        for attempt in range(max_attempts):
            username = fake.user_name()
            # Проверяем, что username не содержит "harkan" (в любом регистре)
            if "harkan" not in username.lower():
                return username

        # Если за 10 попыток не получилось - используем fallback
        logger.warning("Не удалось сгенерировать username через Faker без 'harkan', используем fallback")
        return _generate_username_fallback()

    except ImportError:
        # Если Faker не установлен - используем fallback
        logger.warning("Faker не установлен, используем простой генератор username")
        return _generate_username_fallback()


def generate_password() -> str:
    """
    Генерирует случайный пароль.

    Returns:
        Случайный пароль (минимум 8 символов)
    """
    # Используем буквы и цифры
    chars = string.ascii_letters + string.digits
    # Генерируем пароль длиной от 8 до 12 символов
    length = random.randint(8, 12)
    return "".join(random.choice(chars) for _ in range(length))


# ==================== ФУНКЦИИ ПРОВЕРКИ NFT ====================


def check_nft_balance(address: str, token_id: int = BADGE_ID) -> bool:
    """
    Проверяет, есть ли у кошелька NFT Harkan (баланс > 0).
    Использует ERC-1155 стандарт: balanceOf(address account, uint256 id)

    Args:
        address: Адрес кошелька (checksum format)
        token_id: ID токена (по умолчанию BADGE_ID = 1)

    Returns:
        True если есть NFT, False если нет
    """
    try:
        w3 = Web3(Web3.HTTPProvider(RPC_URL_DEFAULT, request_kwargs={"timeout": 30}))

        if not w3.is_connected():
            logger.warning("RPC недоступен при проверке баланса NFT")
            return False

        # ABI для функции balanceOf ERC-1155 (принимает address и uint256 id)
        nft_abi = [
            {
                "inputs": [
                    {"internalType": "address", "name": "account", "type": "address"},
                    {"internalType": "uint256", "name": "id", "type": "uint256"}
                ],
                "name": "balanceOf",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function",
            }
        ]

        contract = w3.eth.contract(
            address=Web3.to_checksum_address(HARKAN_NFT_CONTRACT), abi=nft_abi
        )

        # Вызываем balanceOf(address, token_id) для ERC-1155
        balance = contract.functions.balanceOf(
            Web3.to_checksum_address(address), token_id
        ).call()

        has_nft = balance > 0

        if has_nft:
            logger.info(f"Кошелек {address} уже имеет NFT Harkan (token_id: {token_id}, баланс: {balance})")
        else:
            logger.info(f"Кошелек {address} не имеет NFT Harkan (token_id: {token_id}, баланс: {balance})")

        return has_nft

    except Exception as e:
        logger.error(f"Ошибка при проверке баланса NFT для {address}: {e}")
        return False


# ==================== ФУНКЦИИ РАБОТЫ С API HARKAN ====================


def _get_headers(access_token: Optional[str] = None) -> dict[str, str]:
    """
    Возвращает стандартные заголовки для запросов к API Harkan.

    Args:
        access_token: JWT токен (опционально)

    Returns:
        Словарь с заголовками
    """
    headers = {
        "accept": "*/*",
        "accept-language": "ru",
        "content-type": "application/json",
        "dnt": "1",
        "origin": "https://www.harkan.io",
        "referer": "https://www.harkan.io/",
        "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    }

    if access_token:
        headers["authorization"] = f"Bearer {access_token}"

    return headers


def register_account(
    username: str, password: str, proxy: Optional[ProxyEntry] = None
) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Регистрирует новый аккаунт на Harkan.

    Args:
        username: Имя пользователя
        password: Пароль
        proxy: Прокси для использования (опционально)

    Returns:
        (success: bool, user_id: Optional[str], error: Optional[str])
    """
    session = requests.Session()

    proxies_cfg = None
    if proxy:
        proxies_cfg = {"http": proxy.http_url, "https": proxy.http_url}

    try:
        response = session.post(
            HARKAN_REGISTER_URL,
            json={"username": username, "password": password},
            headers=_get_headers(),
            proxies=proxies_cfg,
            timeout=30,
        )

        response.raise_for_status()
        data = response.json()

        if data.get("ok") and data.get("data", {}).get("ok"):
            user_id = data.get("data", {}).get("user", {}).get("id")
            if user_id:
                logger.success(f"Аккаунт {username} успешно зарегистрирован (user_id: {user_id})")
                return True, user_id, None
            else:
                return False, None, "user_id не найден в ответе"

        return False, None, f"Регистрация не удалась: {data}"

    except requests.exceptions.RequestException as e:
        error_msg = f"Ошибка при регистрации: {e}"
        logger.error(error_msg)
        return False, None, error_msg
    except Exception as e:
        error_msg = f"Неожиданная ошибка при регистрации: {e}"
        logger.error(error_msg)
        return False, None, error_msg


def login_account(
    username: str, password: str, proxy: Optional[ProxyEntry] = None
) -> tuple[bool, Optional[str], Optional[str], Optional[dict], Optional[str]]:
    """
    Логинится в аккаунт Harkan.

    Args:
        username: Имя пользователя
        password: Пароль
        proxy: Прокси для использования (опционально)

    Returns:
        (success: bool, access_token: Optional[str], refresh_token: Optional[str], user_data: Optional[dict], error: Optional[str])
    """
    session = requests.Session()

    proxies_cfg = None
    if proxy:
        proxies_cfg = {"http": proxy.http_url, "https": proxy.http_url}

    try:
        response = session.post(
            HARKAN_LOGIN_URL,
            json={"username": username, "password": password},
            headers=_get_headers(),
            proxies=proxies_cfg,
            timeout=30,
        )

        response.raise_for_status()
        data = response.json()

        access_token = data.get("accessToken")
        refresh_token = data.get("refreshToken")
        user_data = data.get("user", {})

        if access_token:
            logger.success(f"Успешный логин для {username}")
            return True, access_token, refresh_token, user_data, None
        else:
            return False, None, None, None, "accessToken не найден в ответе"

    except requests.exceptions.RequestException as e:
        error_msg = f"Ошибка при логине: {e}"
        logger.error(error_msg)
        return False, None, None, None, error_msg
    except Exception as e:
        error_msg = f"Неожиданная ошибка при логине: {e}"
        logger.error(error_msg)
        return False, None, None, None, error_msg


def get_account_info(
    access_token: str, proxy: Optional[ProxyEntry] = None
) -> tuple[bool, Optional[dict], Optional[str]]:
    """
    Получает информацию об аккаунте.

    Args:
        access_token: JWT токен
        proxy: Прокси для использования (опционально)

    Returns:
        (success: bool, account_data: Optional[dict], error: Optional[str])
    """
    session = requests.Session()

    proxies_cfg = None
    if proxy:
        proxies_cfg = {"http": proxy.http_url, "https": proxy.http_url}

    try:
        response = session.get(
            HARKAN_ME_URL,
            headers=_get_headers(access_token=access_token),
            proxies=proxies_cfg,
            timeout=30,
        )

        response.raise_for_status()
        data = response.json()

        logger.debug(f"Данные аккаунта получены: {data.get('username', 'unknown')}")
        return True, data, None

    except requests.exceptions.RequestException as e:
        error_msg = f"Ошибка при получении данных аккаунта: {e}"
        logger.error(error_msg)
        return False, None, error_msg
    except Exception as e:
        error_msg = f"Неожиданная ошибка при получении данных аккаунта: {e}"
        logger.error(error_msg)
        return False, None, error_msg


def claim_badge(
    access_token: str, wallet_address: str, badge_id: int = BADGE_ID, proxy: Optional[ProxyEntry] = None
) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Подает заявку на клайм NFT бейджа.

    Args:
        access_token: JWT токен
        wallet_address: Адрес кошелька для клайма
        badge_id: ID бейджа (по умолчанию 1)
        proxy: Прокси для использования (опционально)

    Returns:
        (success: bool, claim_id: Optional[str], error: Optional[str])
    """
    session = requests.Session()

    proxies_cfg = None
    if proxy:
        proxies_cfg = {"http": proxy.http_url, "https": proxy.http_url}

    try:
        response = session.post(
            HARKAN_CLAIM_URL,
            json={"badgeId": badge_id, "wallet": wallet_address},
            headers=_get_headers(access_token=access_token),
            proxies=proxies_cfg,
            timeout=30,
        )

        # Логируем статус код и тело ответа для отладки
        logger.debug(f"Статус код ответа: {response.status_code}")
        logger.debug(f"Тело ответа: {response.text[:500]}")

        response.raise_for_status()
        data = response.json()

        # Логируем полный ответ для отладки
        logger.debug(f"Ответ API: {data}")

        # Проверяем успешность: либо есть success=True, либо есть id (что означает успешную заявку)
        claim_id = data.get("id")
        is_success = data.get("success", False) or (claim_id is not None and response.status_code == 200)

        if is_success and claim_id:
            logger.success(f"Заявка на клайм NFT успешно подана (claim_id: {claim_id})")
            return True, claim_id, None
        else:
            # Пытаемся извлечь сообщение об ошибке из разных возможных полей
            error_msg = (
                data.get("message") or 
                data.get("error") or 
                data.get("msg") or
                f"Неизвестная ошибка. Ответ: {data}"  # Если ничего не найдено, выводим весь ответ
            )
            
            # Логируем полный ответ при ошибке
            logger.warning(f"Заявка не подана. Ответ API: {data}")
            logger.error(f"Ошибка при подаче заявки: {error_msg}")
            
            return False, None, error_msg

    except requests.exceptions.HTTPError as e:
        # Обработка HTTP ошибок (4xx, 5xx)
        error_msg = f"HTTP ошибка {e.response.status_code if e.response else 'unknown'}: {e}"
        if e.response:
            try:
                error_data = e.response.json()
                error_msg = f"HTTP {e.response.status_code}: {error_data}"
                logger.debug(f"Тело ошибки: {e.response.text[:500]}")
            except:
                error_msg = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
        logger.error(f"Ошибка при подаче заявки: {error_msg}")
        return False, None, error_msg
    except requests.exceptions.RequestException as e:
        error_msg = f"Ошибка сети при подаче заявки: {e}"
        logger.error(error_msg)
        return False, None, error_msg
    except Exception as e:
        error_msg = f"Неожиданная ошибка при подаче заявки: {e}"
        logger.error(error_msg)
        import traceback
        logger.debug(traceback.format_exc())
        return False, None, error_msg


# ==================== ГЛАВНАЯ ФУНКЦИЯ ОБРАБОТКИ КОШЕЛЬКА ====================


def process_wallet(
    private_key: str,
    wallet_index: int,
    proxies_list: list[ProxyEntry],
    used_proxies_set: set[ProxyEntry],
) -> tuple[bool, str, bool]:
    """
    Обрабатывает один кошелек: проверяет NFT, регистрируется/логинится, подает заявку.

    Args:
        private_key: Приватный ключ кошелька
        wallet_index: Индекс кошелька
        proxies_list: Список доступных прокси
        used_proxies_set: Множество использованных прокси

    Returns:
        (success: bool, wallet_address: str, was_skipped: bool)
        was_skipped: True если кошелек был пропущен (NFT есть или заявка уже подана)
    """
    try:
        # Получаем адрес кошелька
        w3 = Web3()
        account = w3.eth.account.from_key(private_key)
        wallet_address = Web3.to_checksum_address(account.address)

        logger.info(f"=" * 60)
        logger.info(f"Обработка кошелька {wallet_index + 1}: {wallet_address}")
        logger.info(f"=" * 60)

        # 1. Проверка NFT баланса
        if check_nft_balance(wallet_address):
            logger.info(f"[SKIP NFT] {wallet_address} уже имеет NFT Harkan")
            return True, wallet_address, True  # was_skipped = True

        # 2. Проверка БД на наличие аккаунта
        account_data = get_harkan_account(wallet_address, QUESTS_DB_PATH)

        proxy: Optional[ProxyEntry] = None

        if account_data:
            # Аккаунт существует
            logger.info(f"Аккаунт найден в БД для {wallet_address}")

            # Проверяем, подана ли уже заявка
            if is_harkan_claim_requested(wallet_address, QUESTS_DB_PATH):
                logger.info(f"[SKIP DB] {wallet_address} заявка уже подана")
                return True, wallet_address, True  # was_skipped = True

            # Получаем данные из БД
            username = account_data.get("username")
            password = account_data.get("password")
            stored_ip = account_data.get("ip_address")

            # Пытаемся найти прокси по IP из БД или назначить новый
            if stored_ip:
                # Ищем прокси по IP
                for p in proxies_list:
                    if p.host == stored_ip:
                        if p not in used_proxies_set:
                            proxy = p
                            break

            # Если не нашли прокси из БД или он уже использован, назначаем новый
            if not proxy:
                # Назначаем прокси по индексу
                proxy = assign_proxy_to_wallet(wallet_index, proxies_list)
                if proxy in used_proxies_set:
                    logger.warning(f"Прокси {proxy.safe_label} уже использован, пропускаем кошелек")
                    return False, wallet_address, False  # was_skipped = False (ошибка, не пропуск)

            used_proxies_set.add(proxy)

            # Пытаемся залогиниться
            success, access_token, refresh_token, user_data, error = login_account(
                username, password, proxy
            )

            if success and access_token:
                # Задержка после логина, перед получением данных аккаунта
                random_delay(
                    DELAY_AFTER_LOGIN_MIN_SEC,
                    DELAY_AFTER_LOGIN_MAX_SEC,
                    reason="После логина, перед получением данных аккаунта"
                )

                # Получаем данные аккаунта
                success_info, account_info, error_info = get_account_info(access_token, proxy)
                if not success_info:
                    logger.warning(f"Не удалось получить данные аккаунта: {error_info}")

                # Задержка после получения данных аккаунта, перед подачей заявки
                random_delay(
                    DELAY_AFTER_ACCOUNT_INFO_MIN_SEC,
                    DELAY_AFTER_ACCOUNT_INFO_MAX_SEC,
                    reason="После получения данных аккаунта, перед подачей заявки"
                )

                # Логин успешен, подаем заявку
                claim_success, claim_id, claim_error = claim_badge(
                    access_token, wallet_address, BADGE_ID, proxy
                )

                if claim_success and claim_id:
                    # Обновляем БД
                    update_harkan_claim(wallet_address, claim_id, QUESTS_DB_PATH)
                    mark_wallet_completed(wallet_address, "harkan", 1, 1, QUESTS_DB_PATH)
                    logger.success(f"✅ Заявка успешно подана для {wallet_address}")
                    return True, wallet_address, False  # was_skipped = False (обработан)
                else:
                    logger.error(f"Ошибка при подаче заявки: {claim_error}")
                    return False, wallet_address, False  # was_skipped = False (ошибка)
            else:
                # Логин не удался, регистрируем заново
                logger.warning(f"Логин не удался для {username}, регистрируем новый аккаунт")
                # Сбрасываем account_data, чтобы зарегистрировать новый аккаунт
                account_data = None
                # Прокси уже назначен и добавлен в used_proxies_set, используем его для регистрации

        # 3. Регистрация нового аккаунта (если аккаунта нет или логин не удался)
        if not account_data:
            logger.info(f"Создание нового аккаунта для {wallet_address}")

            # Назначаем прокси (если еще не назначен)
            if not proxy:
                proxy = assign_proxy_to_wallet(wallet_index, proxies_list)
                if proxy in used_proxies_set:
                    logger.warning(f"Прокси {proxy.safe_label} уже использован, пропускаем кошелек")
                    return False, wallet_address, False  # was_skipped = False (ошибка, не пропуск)
                used_proxies_set.add(proxy)

        # Генерируем username и password
        max_username_attempts = 5
        username = None
        user_id = None
        # Генерируем пароль один раз для этого аккаунта (используется и для регистрации, и для сохранения в БД)
        # Для каждого нового кошелька будет генерироваться новый уникальный пароль
        password = generate_password()

        for attempt in range(max_username_attempts):
            username = generate_username()
            success, user_id, error = register_account(username, password, proxy)

            if success and user_id:
                break
            elif "username" in str(error).lower() or "already" in str(error).lower():
                logger.warning(f"Username {username} занят, попытка {attempt + 1}/{max_username_attempts}")
                # Задержка между попытками регистрации (если не последняя попытка)
                if attempt < max_username_attempts - 1:
                    random_delay(
                        DELAY_BETWEEN_USERNAME_ATTEMPTS_MIN_SEC,
                        DELAY_BETWEEN_USERNAME_ATTEMPTS_MAX_SEC,
                        reason="Между попытками регистрации (username занят)"
                    )
                continue
            else:
                logger.error(f"Ошибка регистрации: {error}")
                return False, wallet_address, False  # was_skipped = False (ошибка)

        if not username or not user_id:
            logger.error("Не удалось зарегистрировать аккаунт после всех попыток")
            return False, wallet_address, False  # was_skipped = False (ошибка)

        # Выводим данные аккаунта в лог
        logger.info(f"Аккаунт создан - Username: {username}, Password: {password}")

        # Сохраняем аккаунт в БД
        save_harkan_account(
            wallet_address=wallet_address,
            username=username,
            password=password,
            user_id=user_id,
            ip_address=proxy.host if proxy else None,
            access_token=None,  # Получим при логине
            refresh_token=None,
            db_path=QUESTS_DB_PATH,
        )

        # Задержка после регистрации, перед логином
        random_delay(
            DELAY_AFTER_REGISTER_MIN_SEC,
            DELAY_AFTER_REGISTER_MAX_SEC,
            reason="После регистрации, перед логином"
        )

        # Логинимся
        success, access_token, refresh_token, user_data, error = login_account(
            username, password, proxy
        )

        if not success or not access_token:
            logger.error(f"Ошибка при логине после регистрации: {error}")
            return False, wallet_address, False  # was_skipped = False (ошибка)

        # Задержка после логина, перед получением данных аккаунта
        random_delay(
            DELAY_AFTER_LOGIN_MIN_SEC,
            DELAY_AFTER_LOGIN_MAX_SEC,
            reason="После логина, перед получением данных аккаунта"
        )

        # Получаем данные аккаунта
        success, account_info, error = get_account_info(access_token, proxy)
        if not success:
            logger.warning(f"Не удалось получить данные аккаунта: {error}")

        # Задержка после получения данных аккаунта, перед подачей заявки
        random_delay(
            DELAY_AFTER_ACCOUNT_INFO_MIN_SEC,
            DELAY_AFTER_ACCOUNT_INFO_MAX_SEC,
            reason="После получения данных аккаунта, перед подачей заявки"
        )

        # Подаем заявку
        claim_success, claim_id, claim_error = claim_badge(
            access_token, wallet_address, BADGE_ID, proxy
        )

        if claim_success and claim_id:
            # Обновляем БД
            update_harkan_claim(wallet_address, claim_id, QUESTS_DB_PATH)
            mark_wallet_completed(wallet_address, "harkan", 1, 1, QUESTS_DB_PATH)
            logger.success(f"✅ Заявка успешно подана для {wallet_address}")
            return True, wallet_address, False  # was_skipped = False (обработан)
        else:
            logger.error(f"Ошибка при подаче заявки: {claim_error}")
            return False, wallet_address, False  # was_skipped = False (ошибка)

    except Exception as e:
        logger.error(f"Ошибка при обработке кошелька: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return False, wallet_address if "wallet_address" in locals() else "unknown", False  # was_skipped = False (ошибка)


# ==================== ГЛАВНАЯ ФУНКЦИЯ ====================


def run() -> None:
    """
    Главная функция для запуска модуля из main.py.
    Загружает все ключи и прокси, обрабатывает каждый кошелек.
    """
    # Настройка логирования
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        level="INFO",
    )

    try:
        # 1. Инициализация БД
        init_quests_database(QUESTS_DB_PATH)
        init_harkan_accounts_table(QUESTS_DB_PATH)
        logger.info("База данных инициализирована")

        # 2. Загрузка данных
        all_keys = load_all_keys()
        proxies_list = load_proxies()

        logger.info(f"Загружено ключей: {len(all_keys)}")
        logger.info(f"Загружено прокси: {len(proxies_list)}")

        # 3. Валидация прокси
        validate_proxy_count(len(all_keys), len(proxies_list))

        # 4. Запрос задержки между кошельками
        logger.info("=" * 60)
        logger.info("НАСТРОЙКА ЗАДЕРЖКИ МЕЖДУ КОШЕЛЬКАМИ")
        logger.info("=" * 60)

        try:
            min_delay_minutes, max_delay_minutes = get_delay_minutes_from_user()
            logger.info(f"Установлена задержка: {min_delay_minutes}-{max_delay_minutes} минут между кошельками")
        except (KeyboardInterrupt, EOFError):
            # Если пользователь прервал ввод - используем значение по умолчанию
            min_delay_minutes = DEFAULT_DELAY_MIN_MINUTES
            max_delay_minutes = DEFAULT_DELAY_MAX_MINUTES
            logger.info(f"Используется значение по умолчанию: {min_delay_minutes}-{max_delay_minutes} минут")
        except Exception as e:
            # При любой ошибке - используем значение по умолчанию
            min_delay_minutes = DEFAULT_DELAY_MIN_MINUTES
            max_delay_minutes = DEFAULT_DELAY_MAX_MINUTES
            logger.warning(f"Ошибка при вводе параметров: {e}, используется значение по умолчанию: {min_delay_minutes}-{max_delay_minutes} минут")

        # 5. Основной цикл
        indices = list(range(len(all_keys)))
        random.shuffle(indices)

        used_proxies_set: set[ProxyEntry] = set()
        wallets_completed = 0
        wallets_skipped = 0
        wallets_failed = 0

        for i, key_index in enumerate(indices):
            private_key = all_keys[key_index]

            success, wallet_address, was_skipped = process_wallet(
                private_key, key_index, proxies_list, used_proxies_set
            )

            if success:
                if was_skipped:
                    wallets_skipped += 1
                else:
                    wallets_completed += 1
            else:
                wallets_failed += 1

            # Задержка между кошельками (только если кошелек был обработан, не пропущен)
            if i < len(indices) - 1 and not was_skipped:
                logger.info(f"Ожидание {min_delay_minutes}-{max_delay_minutes} минут перед следующим кошельком...")
                random_delay_minutes(
                    min_delay_minutes,
                    max_delay_minutes,
                    reason="Между кошельками"
                )

        # Статистика
        logger.info("=" * 60)
        logger.info("СТАТИСТИКА")
        logger.info("=" * 60)
        logger.info(f"Успешно обработано: {wallets_completed}")
        logger.info(f"Ошибок: {wallets_failed}")
        logger.info(f"Всего обработано: {wallets_completed + wallets_failed}")

    except FileNotFoundError as e:
        logger.error(f"{e}")
        raise SystemExit(1)
    except ValueError as e:
        logger.error(f"{e}")
        raise SystemExit(1)
    except RuntimeError as e:
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

