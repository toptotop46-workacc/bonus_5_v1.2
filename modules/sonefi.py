#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import random
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import requests
from loguru import logger
from web3 import Web3

# Позволяет запускать файл напрямую: `python modules/sonefi.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    root_s = str(PROJECT_ROOT)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)

import re

# Импорт функций для работы с БД
try:
    from modules.db_utils import (
        init_quests_database,
        is_wallet_completed,
        mark_wallet_completed,
        QUESTS_DB_PATH,
    )
except ImportError:
    def init_quests_database(*args, **kwargs):
        pass

    def is_wallet_completed(*args, **kwargs):
        return False

    def mark_wallet_completed(*args, **kwargs):
        pass

    QUESTS_DB_PATH = PROJECT_ROOT / "quests.db"


def load_private_keys():
    """Загружает приватные ключи из файла keys.txt"""
    keys_file = PROJECT_ROOT / "keys.txt"
    if not keys_file.exists():
        print("❌ Файл keys.txt не найден")
        return []

    keys = []
    with open(keys_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if re.match(r"^0x[a-fA-F0-9]{64}$", line):
                    keys.append(line)
                elif re.match(r"^[a-fA-F0-9]{64}$", line):
                    keys.append("0x" + line)
                else:
                    print(f"⚠️ Неверный формат ключа: {line[:20]}...")

    return keys


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
            if line and not line.startswith("#"):
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
            if line and not line.startswith("#"):
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
PORTAL_PROFILE_URL = "https://portal.soneium.org/api/profile/bonus-dapp"
PROXY_FILE = PROJECT_ROOT / "proxy.txt"

# Параметры торговли
MIN_COLLATERAL = int(10.01 * 10**6)  # 10.01 USDC.e
MAX_COLLATERAL = int(10.99 * 10**6)  # 10.99 USDC.e
MIN_LEVERAGE = 1.1
MAX_LEVERAGE = 1.49
QUEST_ID = "sonefi_5"

# URL SoneFi
SONEFI_URL = "https://sonefi.xyz/#/tradePremium"

# === Конфиг для работы с Uniswap ===
RPC_URL_DEFAULT = "https://soneium-rpc.publicnode.com"
CHAIN_ID = 1868

# Адреса контрактов Uniswap v4 на Soneium
QUOTER_ADDRESS = "0x3972c00f7ed4885e145823eb7c655375d275a1c5"
UNIVERSAL_ROUTER_ADDRESS = "0x0e2850543f69f678257266e0907ff9a58b3f13de"

# Адрес USDCE на Soneium
USDCE_ADDRESS = "0xbA9986D2381edf1DA03B0B9c1f8b00dc4AacC369"

# NATIVE ETH адрес
NATIVE_ETH_ADDRESS = "0x0000000000000000000000000000000000000000"

# Параметры пула
FEE_TIER = 500  # 0.05%
TICK_SPACING = 10

# ABI для ERC20 токена (баланс)
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
]

# ABI для Quoter
QUOTER_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {
                        "components": [
                            {"internalType": "address", "name": "currency0", "type": "address"},
                            {"internalType": "address", "name": "currency1", "type": "address"},
                            {"internalType": "uint24", "name": "fee", "type": "uint24"},
                            {"internalType": "int24", "name": "tickSpacing", "type": "int24"},
                            {"internalType": "contract IHooks", "name": "hooks", "type": "address"},
                        ],
                        "internalType": "struct PoolKey",
                        "name": "poolKey",
                        "type": "tuple",
                    },
                    {"internalType": "bool", "name": "zeroForOne", "type": "bool"},
                    {"internalType": "uint128", "name": "exactAmount", "type": "uint128"},
                    {"internalType": "bytes", "name": "hookData", "type": "bytes"},
                ],
                "internalType": "struct IV4Quoter.QuoteExactSingleParams",
                "name": "params",
                "type": "tuple",
            }
        ],
        "name": "quoteExactInputSingle",
        "outputs": [
            {"internalType": "uint256", "name": "amountOut", "type": "uint256"},
            {"internalType": "uint256", "name": "gasEstimate", "type": "uint256"},
        ],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

# ABI для Universal Router
UNIVERSAL_ROUTER_ABI = [
    {
        "inputs": [
            {"internalType": "bytes", "name": "commands", "type": "bytes"},
            {"internalType": "bytes[]", "name": "inputs", "type": "bytes[]"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"},
        ],
        "name": "execute",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function",
    }
]


@dataclass(frozen=True)
class ProxyEntry:
    host: str
    port: int
    username: str
    password: str

    @property
    def http_url(self) -> str:
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


def _fetch_portal_bonus_profile(address: str, max_attempts: int = 30) -> list[dict[str, Any]]:
    """
    Запрашивает профиль из Portal API через случайные прокси.
    """
    proxies_all = load_proxies()
    session = requests.Session()

    last_err: Exception | None = None
    attempts = max(1, int(max_attempts))
    pool: list[ProxyEntry] = proxies_all[:]
    random.shuffle(pool)

    for attempt in range(1, attempts + 1):
        p: Optional[ProxyEntry]
        proxies_cfg: Optional[dict[str, str]]

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
                PORTAL_PROFILE_URL,
                params={"address": address},
                timeout=30,
                proxies=proxies_cfg,
                headers={
                    "accept": "application/json",
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
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
            last_err = e
            logger.debug(
                "[PORTAL] attempt {}/{} proxy={} err={}",
                attempt,
                attempts,
                (p.safe_label if p else "none"),
                e,
            )
            time.sleep(random.uniform(0.4, 1.2))

    raise RuntimeError(f"Portal недоступен после {attempts} попыток (прокси ротировались): {last_err}")


def _extract_sonefi_progress(profile: list[dict[str, Any]]) -> tuple[int, int]:
    """Извлекает прогресс квеста sonefi_5 из ответа Portal API"""
    candidates: list[dict[str, Any]] = []
    for item in profile:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id", "")).lower()
        if item_id == QUEST_ID or item_id.startswith("sonefi_"):
            candidates.append(item)

    if not candidates:
        raise RuntimeError(f"В ответе portal не найден квест {QUEST_ID} или sonefi_*")

    candidates.sort(key=lambda x: int(x.get("week", 0) or 0), reverse=True)
    sonefi = candidates[0]
    quests = sonefi.get("quests") or []
    if not isinstance(quests, list) or not quests:
        raise RuntimeError(f"В {QUEST_ID} отсутствует quests[]")

    req = 0
    comp = 0
    for q in quests:
        if not isinstance(q, dict):
            continue
        if str(q.get("unit", "")).lower() != "txs":
            continue
        req = max(req, int(q.get("required", 0) or 0))
        comp = max(comp, int(q.get("completed", 0) or 0))

    if req <= 0:
        q0 = quests[0] if isinstance(quests[0], dict) else {}
        req = int(q0.get("required", 0) or 0)
        comp = int(q0.get("completed", 0) or 0)

    return comp, req


def get_usdce_balance(address: str, rpc_url: str = RPC_URL_DEFAULT) -> float:
    """
    Получает баланс USDC.e на кошельке.
    
    Args:
        address: Адрес кошелька (checksum format)
        rpc_url: URL RPC ноды (по умолчанию Soneium RPC)
    
    Returns:
        Баланс в USDC.e как float
    """
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        
        if not w3.is_connected():
            raise RuntimeError("RPC недоступен (w3.is_connected() == False)")
        
        usdce_contract = w3.eth.contract(
            address=Web3.to_checksum_address(USDCE_ADDRESS),
            abi=ERC20_ABI
        )
        
        # Получаем баланс в наименьших единицах (6 decimals для USDC.e)
        balance_raw = usdce_contract.functions.balanceOf(
            Web3.to_checksum_address(address)
        ).call()
        
        # Конвертируем в USDC.e (6 decimals)
        balance_usdce = float(balance_raw) / (10 ** 6)
        
        return balance_usdce
    except Exception as e:
        logger.error(f"Ошибка при получении баланса USDC.e для {address}: {e}")
        raise


def get_eth_balance(address: str, rpc_url: str = RPC_URL_DEFAULT) -> float:
    """
    Получает баланс ETH на кошельке в ETH (не в Wei).
    
    Args:
        address: Адрес кошелька (checksum format)
        rpc_url: URL RPC ноды (по умолчанию Soneium RPC)
    
    Returns:
        Баланс в ETH как float
    """
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        
        if not w3.is_connected():
            raise RuntimeError("RPC недоступен (w3.is_connected() == False)")
        
        # Получаем баланс в Wei
        balance_wei = w3.eth.get_balance(Web3.to_checksum_address(address))
        
        # Конвертируем в ETH
        balance_eth = float(Web3.from_wei(balance_wei, "ether"))
        
        return balance_eth
    except Exception as e:
        logger.error(f"Ошибка при получении баланса ETH для {address}: {e}")
        raise


def get_eth_usdce_rate(w3: Web3, quoter_address: str, amount_eth: float = 0.001) -> float:
    """
    Получает курс ETH/USDC.e через Uniswap Quoter.
    
    Args:
        w3: Web3 экземпляр
        quoter_address: Адрес контракта Quoter
        amount_eth: Сумма ETH для получения котировки (по умолчанию 0.001 ETH)
    
    Returns:
        Курс ETH/USDC.e (сколько USDC.e за 1 ETH)
    """
    try:
        quoter = w3.eth.contract(
            address=Web3.to_checksum_address(quoter_address),
            abi=QUOTER_ABI
        )
        
        amount_wei = int(Web3.to_wei(amount_eth, "ether"))
        
        # Формируем PoolKey
        pool_key_tuple = (
            Web3.to_checksum_address(NATIVE_ETH_ADDRESS),
            Web3.to_checksum_address(USDCE_ADDRESS),
            FEE_TIER,
            TICK_SPACING,
            Web3.to_checksum_address("0x0000000000000000000000000000000000000000"),
        )
        
        # Формируем параметры
        params_tuple = (
            pool_key_tuple,
            True,  # zeroForOne = True
            amount_wei,
            b"",
        )
        
        result = quoter.functions.quoteExactInputSingle(params_tuple).call()
        amount_out = result[0]
        
        # USDC.e имеет 6 decimals
        amount_out_usdce = float(amount_out) / (10 ** 6)
        
        # Вычисляем курс (USDC.e за 1 ETH)
        rate = amount_out_usdce / amount_eth
        
        return rate
    except Exception as e:
        logger.error(f"Ошибка при получении курса ETH/USDC.e: {e}")
        raise


def calculate_required_eth_for_swap(
    swap_amount_usdce: float,
    eth_usdce_rate: float,
    remaining_txs: int
) -> float:
    """
    Вычисляет необходимую сумму ETH для обмена с учетом всех комиссий.
    
    Args:
        swap_amount_usdce: Сумма USDC.e для обмена
        eth_usdce_rate: Курс ETH/USDC.e
        remaining_txs: Количество оставшихся транзакций
    
    Returns:
        Необходимая сумма ETH
    """
    # ETH для обмена
    swap_eth_cost = swap_amount_usdce / eth_usdce_rate
    
    # Комиссия Uniswap (газ)
    gas_uniswap = 0.00015
    
    # Комиссии SoneFi (0.00004 ETH за каждую транзакцию: открытие + закрытие)
    sonefi_fees = 0.00004 * remaining_txs
    
    # Резерв для комиссий
    reserve = 0.0003
    
    required_eth = swap_eth_cost + gas_uniswap + sonefi_fees + reserve
    
    return required_eth


def swap_eth_to_usdce(
    w3: Web3,
    private_key: str,
    swap_amount_usdce: float,
    slippage: float = 1.5,
    rpc_url: str = RPC_URL_DEFAULT
) -> bool:
    """
    Обменивает ETH на USDC.e через Uniswap v4.
    
    Args:
        w3: Web3 экземпляр
        private_key: Приватный ключ для подписания транзакции
        swap_amount_usdce: Сумма USDC.e для получения (10.49-10.99)
        slippage: Проскальзывание в процентах (по умолчанию 1.5%)
    
    Returns:
        True если обмен выполнен успешно, False в случае ошибки
    """
    try:
        # Импортируем функции из uniswap.py
        from modules.uniswap import (
            encode_v4_swap_command,
            execute_v4_swap,
            simulate_v4_swap,
        )
        
        account = w3.eth.account.from_key(private_key)
        wallet_address = account.address
        
        # Получаем курс для расчета суммы ETH
        eth_usdce_rate = get_eth_usdce_rate(w3, QUOTER_ADDRESS)
        
        # Вычисляем сумму ETH для обмена
        swap_amount_eth = swap_amount_usdce / eth_usdce_rate
        
        # Учитываем проскальзывание (увеличиваем сумму на slippage%)
        swap_amount_eth_with_slippage = swap_amount_eth * (1 + slippage / 100)
        
        # Конвертируем в Wei
        swap_amount_wei = int(Web3.to_wei(swap_amount_eth_with_slippage, "ether"))
        
        # Симулируем swap для проверки
        logger.info(f"Симуляция обмена {swap_amount_eth_with_slippage:.6f} ETH на ~{swap_amount_usdce:.2f} USDC.e...")
        simulation_result = simulate_v4_swap(
            w3=w3,
            quoter_address=QUOTER_ADDRESS,
            token_in=NATIVE_ETH_ADDRESS,
            token_out=USDCE_ADDRESS,
            amount_in_wei=swap_amount_wei,
            fee=FEE_TIER,
            tick_spacing=TICK_SPACING,
        )
        
        if not simulation_result:
            logger.warning("Не удалось выполнить симуляцию обмена")
            return False
        
        expected_usdce = simulation_result['amount_out_formatted']
        logger.info(f"Ожидаемая выходная сумма: {expected_usdce:.6f} USDC.e")
        
        # Проверяем, что ожидаемая сумма достаточна
        if expected_usdce < swap_amount_usdce * (1 - slippage / 100):
            logger.warning(f"Ожидаемая сумма {expected_usdce:.6f} USDC.e меньше минимальной {swap_amount_usdce * (1 - slippage / 100):.2f} USDC.e")
            return False
        
        # Выполняем реальную транзакцию
        logger.info(f"Выполнение обмена {swap_amount_eth_with_slippage:.6f} ETH на USDC.e...")
        tx_hash = execute_v4_swap(
            w3=w3,
            private_key=private_key,
            token_in=NATIVE_ETH_ADDRESS,
            token_out=USDCE_ADDRESS,
            amount_in_wei=swap_amount_wei,
            fee=FEE_TIER,
            tick_spacing=TICK_SPACING,
            recipient=wallet_address,
        )
        
        if tx_hash:
            logger.success(f"Обмен выполнен успешно: {tx_hash}")
            
            # Проверяем баланс после обмена
            time.sleep(3)  # Даём время на обработку транзакции
            new_balance = get_usdce_balance(wallet_address, rpc_url)
            logger.info(f"Новый баланс USDC.e: {new_balance:.2f}")
            
            # Проверяем, что осталось достаточно ETH для комиссий
            eth_balance = get_eth_balance(wallet_address, rpc_url)
            if eth_balance < 0.0007:
                logger.warning(f"Баланс ETH после обмена ({eth_balance:.6f}) меньше резерва (0.0007 ETH)")
            
            return True
        else:
            logger.error("Не удалось выполнить обмен")
            return False
            
    except Exception as e:
        logger.error(f"Ошибка при обмене ETH на USDC.e: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return False


class SoneFi:
    """
    Класс для создания и управления временными браузерами через AdsPower Local API.
    Создает временный профиль Windows, открывает браузер, импортирует кошелек,
    переходит на SoneFi и выполняет торговые операции.
    """

    def __init__(
        self,
        api_key: str,
        api_port: int = 50325,
        base_url: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Инициализация класса SoneFi.

        Args:
            api_key: API ключ для AdsPower
            api_port: Порт API (по умолчанию 50325)
            base_url: Базовый URL API (если не указан, используется local.adspower.net)
            timeout: Таймаут для HTTP запросов в секундах
        """
        self.api_key = api_key
        self.api_port = api_port
        if base_url:
            self.base_url = base_url
        else:
            self.base_url = f"http://local.adspower.net:{api_port}"
        self.timeout = timeout
        self.profile_id: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        })
        self.last_request_time: float = 0.0
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
                extension_id = "acmacodkjbdgmoleebolmdjonilkdbch"
                setup_url = f"chrome-extension://{extension_id}/index.html#/new-user/guide"
                
                page = None
                for existing_page in context.pages:
                    url = existing_page.url
                    if extension_id in url or ("chrome-extension://" in url and "rabby" in url.lower()):
                        page = existing_page
                        if "#/new-user/guide" not in url:
                            await page.goto(setup_url)
                            await asyncio.sleep(2)
                        break

                if not page:
                    page = await context.new_page()
                    await page.goto(setup_url)
                    await asyncio.sleep(3)

                # Шаг 1: Нажимаем "I already have an address"
                await page.wait_for_selector('span:has-text("I already have an address")', timeout=30000)
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
                
                # Закрываем вкладку расширения после успешного импорта
                try:
                    logger.info("Закрытие вкладки расширения кошелька...")
                    await page.close()
                    logger.success("Вкладка расширения закрыта")
                except Exception as e:
                    logger.debug(f"Ошибка при закрытии вкладки расширения: {e}")
                
                return wallet_address

            finally:
                await playwright.stop()

        except Exception as e:
            logger.error(f"Ошибка при импорте кошелька: {e}")
            raise

    async def _navigate_to_sonefi(self, cdp_endpoint: str) -> bool:
        """
        Переходит на страницу SoneFi и ждет загрузки.

        Args:
            cdp_endpoint: CDP endpoint (например, ws://127.0.0.1:9222)
        
        Returns:
            True если успешно перешли на страницу, False в случае ошибки
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

                # Используем существующую страницу или создаем новую
                page = None
                for existing_page in context.pages:
                    if not existing_page.url.startswith("chrome-extension://"):
                        page = existing_page
                        break

                if not page:
                    page = await context.new_page()

                # Переходим на страницу SoneFi
                logger.info(f"Переход на страницу {SONEFI_URL}")
                await page.goto(SONEFI_URL, wait_until="networkidle", timeout=60000)
                await asyncio.sleep(3)  # Даём время на загрузку страницы
                
                logger.success(f"Успешно перешли на страницу {SONEFI_URL}")
                
                # Ищем и нажимаем кнопку "Connect Wallet"
                connect_wallet_clicked = False
                connect_wallet_selectors = [
                    'button.primary-action:has-text("Connect Wallet")',
                    'button.button.primary-action:has-text("Connect Wallet")',
                    'button.primary-action',
                    'button.button.primary-action.w-full.center',
                    'button:has-text("Connect Wallet")',
                    'button:has-text("Connect wallet")',
                    'button:has-text("CONNECT WALLET")',
                    '[role="button"]:has-text("Connect Wallet")',
                    'div:has-text("Connect Wallet")',
                ]
                
                for selector in connect_wallet_selectors:
                    try:
                        logger.info("Ожидание кнопки 'Connect Wallet'...")
                        await page.wait_for_selector(selector, timeout=30000)
                        await page.click(selector)
                        logger.success("Кнопка 'Connect Wallet' нажата успешно")
                        connect_wallet_clicked = True
                        break
                    except Exception as e:
                        logger.debug(f"Не удалось найти кнопку: {e}")
                        continue
                
                if not connect_wallet_clicked:
                    logger.warning("Не удалось найти кнопку 'Connect Wallet', продолжаем...")
                    return True  # Продолжаем даже если не нашли кнопку
                
                # Ждём открытия модального окна
                logger.info("Ожидание открытия модального окна...")
                try:
                    # Ждём появления заголовка модального окна или самого модального окна
                    await page.wait_for_selector('h1#rk_connect_title, [data-testid^="rk-wallet-option"]', timeout=10000)
                    logger.success("Модальное окно открылось")
                except Exception as e:
                    logger.debug(f"Модальное окно не появилось за 10 секунд: {e}")
                
                await asyncio.sleep(1)  # Дополнительная задержка для полной загрузки
                
                # Ищем и нажимаем "Rabby" в модальном окне
                rabby_clicked = False
                rabby_selectors = [
                    'button[data-testid="rk-wallet-option-rabby"]',
                    '[data-testid="rk-wallet-option-rabby"]',
                    'button[data-testid="rk-wallet-option-rabby"] div:has-text("Rabby")',
                    'button:has([data-testid="rk-wallet-option-rabby"])',
                    'div.iekbcc0:has-text("Rabby")',
                    'div:has-text("Rabby")',
                    'span:has-text("Rabby")',
                    'button:has-text("Rabby")',
                    '[role="button"]:has-text("Rabby")',
                ]
                
                for selector in rabby_selectors:
                    try:
                        logger.info("Ожидание элемента 'Rabby' в модальном окне...")
                        await page.wait_for_selector(selector, timeout=30000)
                        await page.click(selector)
                        logger.success("Элемент 'Rabby' нажат успешно")
                        rabby_clicked = True
                        break
                    except Exception as e:
                        logger.debug(f"Не удалось найти элемент: {e}")
                        continue
                
                if not rabby_clicked:
                    logger.warning("Не удалось найти элемент 'Rabby' в модальном окне")
                    return True  # Продолжаем даже если не нашли
                
                # Ждём открытия окна расширения кошелька
                await asyncio.sleep(2)  # Даём время на открытие расширения
                
                # Ищем страницу расширения кошелька
                extension_id = "acmacodkjbdgmoleebolmdjonilkdbch"
                extension_page = None
                
                # Ждём появления страницы расширения (может открыться с задержкой)
                logger.info("Ожидание окна расширения кошелька...")
                for attempt in range(10):  # Пробуем до 10 раз с интервалом 0.5 сек
                    for existing_page in context.pages:
                        if existing_page.url.startswith(f"chrome-extension://{extension_id}/"):
                            extension_page = existing_page
                            break
                    if extension_page:
                        break
                    await asyncio.sleep(0.5)
                
                if not extension_page:
                    logger.warning("Страница расширения кошелька не найдена, пробуем найти любую страницу расширения")
                    # Пробуем найти любую страницу расширения
                    for existing_page in context.pages:
                        if existing_page.url.startswith("chrome-extension://"):
                            extension_page = existing_page
                            logger.info(f"Найдена страница расширения: {extension_page.url}")
                            break
                
                if extension_page:
                    logger.info("Обработка окна расширения кошелька...")
                    
                    # Кликаем на "Connect"
                    connect_clicked = False
                    connect_selectors = [
                        'span:has-text("Connect")',
                        'button:has-text("Connect")',
                        '[role="button"]:has-text("Connect")',
                        'div:has-text("Connect")',
                    ]
                    
                    for selector in connect_selectors:
                        try:
                            logger.info("Ожидание кнопки 'Connect' в расширении...")
                            await extension_page.wait_for_selector(selector, timeout=30000)
                            await extension_page.click(selector)
                            logger.success("Кнопка 'Connect' нажата успешно")
                            connect_clicked = True
                            await asyncio.sleep(2)  # Даём время на открытие нового окна расширения
                            break
                        except Exception as e:
                            logger.debug(f"Не удалось найти кнопку по селектору {selector}: {e}")
                            continue
                    
                    if not connect_clicked:
                        logger.warning("Не удалось найти кнопку 'Connect' в расширении")
                else:
                    logger.warning("Окно расширения кошелька не найдено")
                
                # Ждём завершения подключения и проверяем стабильность соединения
                await asyncio.sleep(3)  # Даём время на завершение подключения
                
                # Возвращаемся на основную страницу для проверки
                logger.info("Проверка стабильности соединения...")
                try:
                    # Проверяем наличие элемента "Stable" (стабильное соединение)
                    stable_found = False
                    try:
                        # Пробуем найти через locator с текстом и классом
                        stable_element = page.locator('div:has-text("Stable")').first
                        if await stable_element.is_visible(timeout=10000):
                            # Проверяем, что у элемента правильный класс (зелёный цвет)
                            class_attr = await stable_element.get_attribute('class')
                            if class_attr and ('text-[#4FA480]' in class_attr or '4FA480' in class_attr):
                                logger.success("Соединение стабильное (найден элемент 'Stable')")
                                stable_found = True
                            else:
                                logger.debug(f"Элемент 'Stable' найден, но класс не соответствует: {class_attr}")
                    except Exception as e:
                        logger.debug(f"Элемент 'Stable' не найден: {e}")
                    
                    # Альтернативный способ - через evaluate
                    if not stable_found:
                        try:
                            stable_exists = await page.evaluate("""
                                () => {
                                    const elements = Array.from(document.querySelectorAll('div'));
                                    return elements.some(el => {
                                        const text = el.textContent || '';
                                        const className = el.className || '';
                                        return text.includes('Stable') && 
                                               (className.includes('text-[#4FA480]') || 
                                                className.includes('4FA480') ||
                                                getComputedStyle(el).color.includes('rgb(79, 164, 128)'));
                                    });
                                }
                            """)
                            if stable_exists:
                                logger.success("Соединение стабильное (найден элемент 'Stable' через evaluate)")
                                stable_found = True
                        except Exception as e:
                            logger.debug(f"Не удалось проверить 'Stable' через evaluate: {e}")
                    
                    if not stable_found:
                        logger.warning("Элемент 'Stable' не найден, соединение может быть нестабильным")
                    
                    # Проверяем, что выбранная пара - BTC-USD
                    logger.info("Проверка выбранной торговой пары...")
                    btc_usd_selectors = [
                        'text=/BTC-USD/i',
                        'div:has-text("BTC-USD")',
                        'span:has-text("BTC-USD")',
                        'button:has-text("BTC-USD")',
                    ]
                    
                    btc_usd_found = False
                    for selector in btc_usd_selectors:
                        try:
                            element = page.locator(selector).first
                            if await element.is_visible(timeout=5000):
                                logger.success("Торговая пара BTC-USD выбрана")
                                btc_usd_found = True
                                break
                        except Exception as e:
                            logger.debug(f"Пара BTC-USD не найдена по селектору {selector}: {e}")
                            continue
                    
                    if not btc_usd_found:
                        logger.warning("Торговая пара BTC-USD не найдена на экране")
                    
                except Exception as e:
                    logger.warning(f"Ошибка при проверке соединения и торговой пары: {e}")
                
                logger.success("Подключение кошелька Rabby инициировано")
                return True

            finally:
                await playwright.stop()

        except Exception as e:
            logger.error(f"Ошибка при переходе на SoneFi: {e}")
            return False

    async def _execute_trade(self, cdp_endpoint: str, wallet_address: Optional[str] = None) -> bool:
        """
        Выполняет торговую операцию на SoneFi: выбирает случайное направление,
        выставляет Market, вводит случайную сумму и плечо, открывает позицию.

        Args:
            cdp_endpoint: CDP endpoint (например, ws://127.0.0.1:9222)
            wallet_address: Адрес кошелька для проверки баланса (опционально)
        
        Returns:
            True если операция выполнена успешно, False в случае ошибки
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

                # Находим страницу SoneFi (не расширение)
                page = None
                for existing_page in context.pages:
                    if not existing_page.url.startswith("chrome-extension://") and "sonefi" in existing_page.url.lower():
                        page = existing_page
                        break

                if not page:
                    logger.error("Страница SoneFi не найдена")
                    return False

                # Ждём загрузки страницы
                await asyncio.sleep(2)
                
                # 1. Выбираем случайное направление (Long/Short)
                direction = random.choice(["Long", "Short"])
                logger.info(f"Выбор направления: {direction}")
                
                direction_selectors = [
                    f'div.Tab-option:has-text("{direction}")',
                    f'div.Tab-option span:has-text("{direction}")',
                    f'div:has-text("{direction}")',
                ]
                
                direction_clicked = False
                for selector in direction_selectors:
                    try:
                        await page.wait_for_selector(selector, timeout=10000)
                        element = page.locator(selector).first
                        if await element.is_visible():
                            await element.click()
                            logger.success(f"Направление {direction} выбрано")
                            direction_clicked = True
                            await asyncio.sleep(1)
                            break
                    except Exception as e:
                        logger.debug(f"Не удалось выбрать направление по селектору {selector}: {e}")
                        continue
                
                if not direction_clicked:
                    logger.warning(f"Не удалось выбрать направление {direction}")
                    return False
                
                # 2. Убеждаемся, что выбран Market
                logger.info("Проверка типа ордера Market...")
                market_selectors = [
                    'div.Tab-option.active:has-text("Market")',
                    'div.Tab-option:has-text("Market")',
                    'div.Exchange-swap-order-type-tabs .Tab-option:has-text("Market")',
                ]
                
                market_selected = False
                for selector in market_selectors:
                    try:
                        element = page.locator(selector).first
                        if await element.is_visible():
                            # Проверяем, активен ли Market
                            class_attr = await element.get_attribute('class')
                            if class_attr and 'active' in class_attr:
                                logger.success("Market уже выбран")
                                market_selected = True
                                break
                            else:
                                # Если не активен, кликаем
                                await element.click()
                                logger.success("Market выбран")
                                market_selected = True
                                await asyncio.sleep(1)
                                break
                    except Exception as e:
                        logger.debug(f"Не удалось найти Market по селектору {selector}: {e}")
                        continue
                
                if not market_selected:
                    logger.warning("Не удалось выбрать Market")
                    return False
                
                # 3. Вводим случайную сумму от 10.01 до 10.99 (но не больше баланса)
                # Получаем баланс USDC.e для ограничения суммы
                balance_usdce = 10.99  # Значение по умолчанию
                if wallet_address:
                    try:
                        balance_usdce = get_usdce_balance(wallet_address, RPC_URL_DEFAULT)
                        logger.debug(f"Текущий баланс USDC.e: {balance_usdce:.2f}")
                    except Exception as e:
                        logger.warning(f"Не удалось получить баланс USDC.e: {e}, используем максимальное значение")
                        balance_usdce = 10.99
                
                # Ограничиваем максимальную сумму балансом минус 0.01 для надёжности, но не меньше 10.01
                max_amount = min(10.99, balance_usdce - 0.01)
                if max_amount < 10.01:
                    logger.warning(f"Баланс USDC.e ({balance_usdce:.2f}) недостаточен для открытия позиции (требуется минимум 10.02)")
                    return False
                
                # Генерируем случайную сумму от 10.01 до max_amount
                amount = round(random.uniform(10.01, max_amount), 2)
                logger.info(f"Ввод суммы: {amount} (баланс: {balance_usdce:.2f}, максимум: {max_amount:.2f})")
                
                amount_input_selectors = [
                    'input.Exchange-swap-input',
                    'input[type="text"][inputmode="decimal"]',
                    'input[placeholder="0.0"]',
                ]
                
                amount_entered = False
                for selector in amount_input_selectors:
                    try:
                        await page.wait_for_selector(selector, timeout=10000)
                        element = page.locator(selector).first
                        if await element.is_visible():
                            await element.click()
                            await element.fill("")  # Очищаем поле
                            await element.type(str(amount), delay=50)
                            logger.success(f"Сумма {amount} введена")
                            amount_entered = True
                            await asyncio.sleep(1)
                            break
                    except Exception as e:
                        logger.debug(f"Не удалось ввести сумму по селектору {selector}: {e}")
                        continue
                
                if not amount_entered:
                    logger.warning("Не удалось ввести сумму")
                    return False
                
                # 4. Выставляем случайное плечо от 1.1 до 1.49
                leverage = round(random.uniform(1.1, 1.49), 2)
                logger.info(f"Выставление плеча: {leverage}x")
                
                leverage_input_selectors = [
                    'input.leverage-input',
                    'input[class*="leverage-input"]',
                    'input[placeholder="-.--"]',
                ]
                
                leverage_set = False
                for selector in leverage_input_selectors:
                    try:
                        await page.wait_for_selector(selector, timeout=10000)
                        element = page.locator(selector).first
                        if await element.is_visible():
                            await element.click()
                            await element.fill("")  # Очищаем поле
                            await element.type(str(leverage), delay=50)
                            logger.success(f"Плечо {leverage}x установлено")
                            leverage_set = True
                            await asyncio.sleep(1)
                            break
                    except Exception as e:
                        logger.debug(f"Не удалось установить плечо по селектору {selector}: {e}")
                        continue
                
                if not leverage_set:
                    logger.warning("Не удалось установить плечо")
                    return False
                
                # Ждём обновления кнопки (она должна стать активной)
                await asyncio.sleep(2)
                
                # 5. Проверяем, нужен ли апрув USDC.e
                logger.info("Проверка необходимости апрува USDC.e...")
                approve_needed = False
                approve_button_selectors = [
                    'button:has-text("Approve USDC.e")',
                    'button.button.primary-action:has-text("Approve")',
                    'button.primary-action:has-text("Approve")',
                    'button:has-text("Approve")',
                ]
                
                for selector in approve_button_selectors:
                    try:
                        approve_button = page.locator(selector).first
                        if await approve_button.is_visible(timeout=3000):
                            button_text_content = await approve_button.text_content()
                            if button_text_content and "Approve" in button_text_content and "USDC.e" in button_text_content:
                                logger.info("Найдена кнопка 'Approve USDC.e', требуется апрув")
                                approve_needed = True
                                break
                    except Exception:
                        continue
                
                if approve_needed:
                    # Нажимаем кнопку "Approve USDC.e"
                    logger.info("Нажатие кнопки 'Approve USDC.e'...")
                    approve_clicked = False
                    
                    for selector in approve_button_selectors:
                        try:
                            approve_button = page.locator(selector).first
                            if await approve_button.is_visible(timeout=5000):
                                button_text_content = await approve_button.text_content()
                                if button_text_content and "Approve" in button_text_content:
                                    await approve_button.click()
                                    logger.success("Кнопка 'Approve USDC.e' нажата")
                                    approve_clicked = True
                                    await asyncio.sleep(2)
                                    break
                        except Exception as e:
                            logger.debug(f"Не удалось найти кнопку апрува по селектору {selector}: {e}")
                            continue
                    
                    if not approve_clicked:
                        logger.warning("Не удалось нажать кнопку 'Approve USDC.e'")
                        return False
                    
                    # Ждём открытия окна расширения кошелька для подтверждения апрува
                    logger.info("Ожидание открытия окна расширения кошелька для подтверждения апрува...")
                    extension_id = "acmacodkjbdgmoleebolmdjonilkdbch"
                    approve_extension_page = None
                    
                    # Ждём появления страницы расширения
                    for attempt in range(15):
                        for existing_page in context.pages:
                            if existing_page.url.startswith(f"chrome-extension://{extension_id}/"):
                                approve_extension_page = existing_page
                                break
                        if approve_extension_page:
                            break
                        await asyncio.sleep(1)
                    
                    if approve_extension_page:
                        logger.success("Окно расширения кошелька открыто для подтверждения апрува")
                        await asyncio.sleep(2)
                        
                        # Нажимаем кнопку "Sign" в окне расширения
                        logger.info("Поиск кнопки 'Sign' в окне расширения кошелька для апрува...")
                        approve_sign_clicked = False
                        
                        approve_sign_selectors = [
                            'button:has-text("Sign")',
                            'span:has-text("Sign")',
                            'div:has-text("Sign")',
                            '[role="button"]:has-text("Sign")',
                            'button.primary-action:has-text("Sign")',
                        ]
                        
                        for selector in approve_sign_selectors:
                            try:
                                approve_sign_button = approve_extension_page.locator(selector).first
                                if await approve_sign_button.is_visible(timeout=5000):
                                    await approve_sign_button.click()
                                    logger.success("Кнопка 'Sign' для апрува нажата")
                                    approve_sign_clicked = True
                                    await asyncio.sleep(2)
                                    break
                            except Exception as e:
                                logger.debug(f"Не удалось найти кнопку 'Sign' по селектору {selector}: {e}")
                                continue
                        
                        if not approve_sign_clicked:
                            logger.warning("Кнопка 'Sign' не найдена, пробуем альтернативные варианты...")
                            try:
                                all_buttons = approve_extension_page.locator('button')
                                count = await all_buttons.count()
                                for i in range(count):
                                    button = all_buttons.nth(i)
                                    if await button.is_visible(timeout=2000):
                                        button_text = await button.text_content()
                                        if button_text and "Sign" in button_text:
                                            await button.click()
                                            logger.success(f"Кнопка 'Sign' нажата (найдена по тексту: '{button_text}')")
                                            approve_sign_clicked = True
                                            await asyncio.sleep(2)
                                            break
                            except Exception as e:
                                logger.debug(f"Ошибка при поиске кнопки 'Sign': {e}")
                        
                        # Нажимаем кнопку "Confirm" в окне расширения
                        logger.info("Поиск кнопки 'Confirm' в окне расширения кошелька для апрува...")
                        await asyncio.sleep(1)
                        
                        approve_confirm_clicked = False
                        
                        approve_confirm_selectors = [
                            'button:has-text("Confirm")',
                            'span:has-text("Confirm")',
                            'div:has-text("Confirm")',
                            '[role="button"]:has-text("Confirm")',
                            'button.primary-action:has-text("Confirm")',
                        ]
                        
                        for selector in approve_confirm_selectors:
                            try:
                                approve_confirm_button = approve_extension_page.locator(selector).first
                                if await approve_confirm_button.is_visible(timeout=5000):
                                    await approve_confirm_button.click()
                                    logger.success("Кнопка 'Confirm' для апрува нажата")
                                    approve_confirm_clicked = True
                                    await asyncio.sleep(2)
                                    break
                            except Exception as e:
                                logger.debug(f"Не удалось найти кнопку 'Confirm' по селектору {selector}: {e}")
                                continue
                        
                        if not approve_confirm_clicked:
                            logger.warning("Не удалось найти кнопку 'Confirm', пробуем альтернативные варианты...")
                            try:
                                all_buttons = approve_extension_page.locator('button')
                                count = await all_buttons.count()
                                for i in range(count):
                                    button = all_buttons.nth(i)
                                    if await button.is_visible(timeout=2000):
                                        button_text = await button.text_content()
                                        if button_text and "Confirm" in button_text:
                                            await button.click()
                                            logger.success(f"Кнопка 'Confirm' нажата (найдена по тексту: '{button_text}')")
                                            approve_confirm_clicked = True
                                            await asyncio.sleep(2)
                                            break
                            except Exception as e:
                                logger.debug(f"Ошибка при поиске кнопки 'Confirm': {e}")
                        
                        if approve_confirm_clicked:
                            logger.success("Апрув USDC.e подтвержден в кошельке")
                            await asyncio.sleep(3)  # Даём время на обработку апрува
                        else:
                            logger.warning("Кнопка 'Confirm' не найдена, возможно апрув уже подтвержден")
                    else:
                        logger.warning("Окно расширения кошелька не найдено для подтверждения апрува")
                    
                    # Ждём появления кнопки открытия позиции после апрува
                    await asyncio.sleep(2)
                
                # 6. Нажимаем кнопку открытия позиции
                # Текст кнопки зависит от направления: "Long BTC" для Long, "Short BTC" для Short
                button_text = f"{direction} BTC"
                logger.info(f"Поиск кнопки '{button_text}'...")
                
                # Ждём, пока кнопка станет активной (не disabled) и текст совпадёт
                button_clicked = False
                max_attempts = 10
                for attempt in range(max_attempts):
                    try:
                        # Ищем кнопку с нужным текстом
                        button_locator = page.locator(f'button:has-text("{button_text}")').first
                        
                        if await button_locator.is_visible(timeout=2000):
                            # Проверяем, что кнопка не disabled
                            is_disabled = await button_locator.get_attribute('disabled')
                            if is_disabled:
                                logger.debug(f"Попытка {attempt + 1}/{max_attempts}: кнопка ещё disabled, ждём...")
                                await asyncio.sleep(1)
                                continue
                            
                            # Проверяем текст кнопки
                            button_text_content = await button_locator.text_content()
                            if button_text_content and button_text in button_text_content:
                                await button_locator.click()
                                logger.success(f"Кнопка '{button_text}' нажата")
                                button_clicked = True
                                await asyncio.sleep(2)
                                break
                            else:
                                logger.debug(f"Попытка {attempt + 1}/{max_attempts}: текст кнопки '{button_text_content}' не совпадает, ждём...")
                                await asyncio.sleep(1)
                                continue
                        else:
                            logger.debug(f"Попытка {attempt + 1}/{max_attempts}: кнопка не видна, ждём...")
                            await asyncio.sleep(1)
                            continue
                    except Exception as e:
                        logger.debug(f"Попытка {attempt + 1}/{max_attempts}: ошибка при поиске кнопки: {e}")
                        await asyncio.sleep(1)
                        continue
                
                # Если не нашли кнопку с нужным текстом, пробуем альтернативные селекторы
                if not button_clicked:
                    logger.info("Пробуем альтернативные селекторы для кнопки...")
                    button_selectors = [
                        'button.button.primary-action:not([disabled])',
                        'button.primary-action:not([disabled])',
                        'button:not([disabled]).button.primary-action',
                    ]
                    
                    for selector in button_selectors:
                        try:
                            element = page.locator(selector).first
                            if await element.is_visible(timeout=5000):
                                button_text_content = await element.text_content()
                                if button_text_content and (direction in button_text_content or "BTC" in button_text_content):
                                    await element.click()
                                    logger.success(f"Кнопка нажата (текст: '{button_text_content}')")
                                    button_clicked = True
                                    await asyncio.sleep(2)
                                    break
                        except Exception as e:
                            logger.debug(f"Не удалось нажать кнопку по селектору {selector}: {e}")
                            continue
                
                if not button_clicked:
                    logger.warning(f"Не удалось нажать кнопку '{button_text}'")
                    return False
                
                # 6. Ждём появления модального окна подтверждения
                logger.info("Ожидание модального окна подтверждения...")
                modal_title = f"Confirm {direction}"
                
                modal_found = False
                max_modal_attempts = 10
                for attempt in range(max_modal_attempts):
                    try:
                        # Ищем модальное окно по заголовку
                        modal_title_locator = page.locator(f'div.Modal-title:has-text("{modal_title}")')
                        if await modal_title_locator.is_visible(timeout=2000):
                            logger.success(f"Модальное окно '{modal_title}' найдено")
                            modal_found = True
                            await asyncio.sleep(1)
                            break
                    except Exception as e:
                        logger.debug(f"Попытка {attempt + 1}/{max_modal_attempts}: модальное окно не найдено, ждём...")
                        await asyncio.sleep(1)
                        continue
                
                if not modal_found:
                    # Пробуем найти модальное окно по классу
                    try:
                        modal_content = page.locator('div.Modal-content').first
                        if await modal_content.is_visible(timeout=5000):
                            logger.success("Модальное окно найдено по классу")
                            modal_found = True
                    except Exception as e:
                        logger.debug(f"Модальное окно не найдено по классу: {e}")
                
                if not modal_found:
                    logger.warning("Модальное окно подтверждения не найдено")
                    return False
                
                # 7. Нажимаем кнопку подтверждения в модальном окне
                logger.info(f"Поиск кнопки подтверждения '{direction}' в модальном окне...")
                confirm_button_clicked = False
                
                # Сначала ищем кнопку по точному селектору с текстом
                confirm_button_selectors = [
                    f'button.button.primary-action.w-full.mt-sm.center:has-text("{direction}")',
                    f'button.primary-action.w-full.mt-sm.center:has-text("{direction}")',
                    f'button.w-full.mt-sm.center:has-text("{direction}")',
                    f'button.button.primary-action:has-text("{direction}")',
                    f'button.primary-action:has-text("{direction}")',
                ]
                
                for selector in confirm_button_selectors:
                    try:
                        # Ищем кнопку внутри модального окна
                        confirm_button = page.locator(selector).first
                        if await confirm_button.is_visible(timeout=5000):
                            button_text_content = await confirm_button.text_content()
                            if button_text_content and direction.strip() in button_text_content.strip():
                                await confirm_button.click()
                                logger.success(f"Кнопка подтверждения '{direction}' нажата")
                                confirm_button_clicked = True
                                await asyncio.sleep(2)
                                break
                    except Exception as e:
                        logger.debug(f"Не удалось найти кнопку подтверждения по селектору {selector}: {e}")
                        continue
                
                # Если не нашли по тексту, пробуем найти по классам и проверить текст
                if not confirm_button_clicked:
                    logger.info("Пробуем найти кнопку по классам...")
                    try:
                        # Ищем все кнопки с нужными классами
                        all_confirm_buttons = page.locator('button.button.primary-action.w-full.mt-sm.center')
                        count = await all_confirm_buttons.count()
                        logger.debug(f"Найдено кнопок с классами: {count}")
                        
                        for i in range(count):
                            button = all_confirm_buttons.nth(i)
                            if await button.is_visible(timeout=2000):
                                button_text_content = await button.text_content()
                                logger.debug(f"Текст кнопки {i}: '{button_text_content}'")
                                if button_text_content and direction.strip() in button_text_content.strip():
                                    await button.click()
                                    logger.success(f"Кнопка подтверждения '{direction}' нажата (найдена по классам)")
                                    confirm_button_clicked = True
                                    await asyncio.sleep(2)
                                    break
                    except Exception as e:
                        logger.debug(f"Ошибка при поиске кнопки по классам: {e}")
                
                # Последняя попытка - ищем любую кнопку с текстом direction внутри модального окна
                if not confirm_button_clicked:
                    logger.info("Последняя попытка - поиск любой кнопки с нужным текстом...")
                    try:
                        # Ищем кнопку внутри модального окна
                        modal_button = page.locator(f'div.Modal-content button:has-text("{direction}")').first
                        if await modal_button.is_visible(timeout=5000):
                            await modal_button.click()
                            logger.success(f"Кнопка подтверждения '{direction}' нажата (найдена внутри модального окна)")
                            confirm_button_clicked = True
                            await asyncio.sleep(2)
                    except Exception as e:
                        logger.debug(f"Не удалось найти кнопку внутри модального окна: {e}")
                
                if not confirm_button_clicked:
                    logger.warning(f"Не удалось нажать кнопку подтверждения '{direction}'")
                    return False
                
                # 8. Ждём открытия окна расширения кошелька для подтверждения транзакции
                logger.info("Ожидание открытия окна расширения кошелька...")
                extension_id = "acmacodkjbdgmoleebolmdjonilkdbch"
                extension_page = None
                
                # Ждём появления страницы расширения
                for attempt in range(15):  # Пробуем до 15 раз с интервалом 1 сек
                    for existing_page in context.pages:
                        if existing_page.url.startswith(f"chrome-extension://{extension_id}/"):
                            extension_page = existing_page
                            break
                    if extension_page:
                        break
                    await asyncio.sleep(1)
                
                if extension_page:
                    logger.success("Окно расширения кошелька открыто для подтверждения транзакции")
                    await asyncio.sleep(2)  # Даём время на загрузку окна расширения
                    
                    # 9. Нажимаем кнопку "Sign" в окне расширения
                    logger.info("Поиск кнопки 'Sign' в окне расширения кошелька...")
                    sign_button_clicked = False
                    
                    sign_button_selectors = [
                        'button:has-text("Sign")',
                        'span:has-text("Sign")',
                        'div:has-text("Sign")',
                        '[role="button"]:has-text("Sign")',
                        'button.primary-action:has-text("Sign")',
                        'button.button:has-text("Sign")',
                    ]
                    
                    for selector in sign_button_selectors:
                        try:
                            sign_button = extension_page.locator(selector).first
                            if await sign_button.is_visible(timeout=5000):
                                await sign_button.click()
                                logger.success("Кнопка 'Sign' нажата")
                                sign_button_clicked = True
                                await asyncio.sleep(2)
                                break
                        except Exception as e:
                            logger.debug(f"Не удалось найти кнопку 'Sign' по селектору {selector}: {e}")
                            continue
                    
                    if not sign_button_clicked:
                        logger.warning("Не удалось найти кнопку 'Sign', пробуем альтернативные варианты...")
                        # Пробуем найти любую кнопку с текстом, содержащим "Sign"
                        try:
                            all_buttons = extension_page.locator('button')
                            count = await all_buttons.count()
                            for i in range(count):
                                button = all_buttons.nth(i)
                                if await button.is_visible(timeout=2000):
                                    button_text = await button.text_content()
                                    if button_text and "Sign" in button_text:
                                        await button.click()
                                        logger.success(f"Кнопка 'Sign' нажата (найдена по тексту: '{button_text}')")
                                        sign_button_clicked = True
                                        await asyncio.sleep(2)
                                        break
                        except Exception as e:
                            logger.debug(f"Ошибка при поиске кнопки 'Sign': {e}")
                    
                    if not sign_button_clicked:
                        logger.warning("Кнопка 'Sign' не найдена, возможно уже нажата или не требуется")
                    
                    # 10. Нажимаем кнопку "Confirm" в окне расширения
                    logger.info("Поиск кнопки 'Confirm' в окне расширения кошелька...")
                    await asyncio.sleep(1)  # Небольшая задержка перед поиском кнопки Confirm
                    
                    confirm_button_clicked = False
                    
                    confirm_button_selectors = [
                        'button:has-text("Confirm")',
                        'span:has-text("Confirm")',
                        'div:has-text("Confirm")',
                        '[role="button"]:has-text("Confirm")',
                        'button.primary-action:has-text("Confirm")',
                        'button.button:has-text("Confirm")',
                    ]
                    
                    for selector in confirm_button_selectors:
                        try:
                            confirm_button = extension_page.locator(selector).first
                            if await confirm_button.is_visible(timeout=5000):
                                await confirm_button.click()
                                logger.success("Кнопка 'Confirm' нажата")
                                confirm_button_clicked = True
                                await asyncio.sleep(2)
                                break
                        except Exception as e:
                            logger.debug(f"Не удалось найти кнопку 'Confirm' по селектору {selector}: {e}")
                            continue
                    
                    if not confirm_button_clicked:
                        logger.warning("Не удалось найти кнопку 'Confirm', пробуем альтернативные варианты...")
                        # Пробуем найти любую кнопку с текстом, содержащим "Confirm"
                        try:
                            all_buttons = extension_page.locator('button')
                            count = await all_buttons.count()
                            for i in range(count):
                                button = all_buttons.nth(i)
                                if await button.is_visible(timeout=2000):
                                    button_text = await button.text_content()
                                    if button_text and "Confirm" in button_text:
                                        await button.click()
                                        logger.success(f"Кнопка 'Confirm' нажата (найдена по тексту: '{button_text}')")
                                        confirm_button_clicked = True
                                        await asyncio.sleep(2)
                                        break
                        except Exception as e:
                            logger.debug(f"Ошибка при поиске кнопки 'Confirm': {e}")
                    
                    if not confirm_button_clicked:
                        logger.warning("Кнопка 'Confirm' не найдена, возможно транзакция уже подтверждена")
                    else:
                        logger.success("Транзакция подтверждена в кошельке")
                        await asyncio.sleep(3)  # Даём время на обработку транзакции
                else:
                    logger.warning("Окно расширения кошелька не найдено, возможно транзакция уже подтверждена")
                
                # 11. Проверяем открытие позиции и закрываем её
                logger.info("Проверка открытия позиции...")
                await asyncio.sleep(5)  # Даём больше времени на открытие позиции
                
                # Убеждаемся, что мы на основной странице SoneFi
                if page.url and "sonefi" in page.url.lower():
                    # Проверяем наличие позиции в списке
                    position_found = False
                    max_position_attempts = 30  # Увеличиваем количество попыток
                    
                    for attempt in range(max_position_attempts):
                        try:
                            # Способ 1: Проверяем вкладку "Positions" (может быть не активной)
                            positions_tab_selectors = [
                                'div.Tab-option.active:has-text("Positions")',
                                'div.Tab-option:has-text("Positions")',
                            ]
                            
                            for tab_selector in positions_tab_selectors:
                                try:
                                    positions_tab = page.locator(tab_selector).first
                                    if await positions_tab.is_visible(timeout=2000):
                                        tab_text = await positions_tab.text_content()
                                        # Проверяем, есть ли число в скобках (например, "Positions (1)")
                                        if tab_text and "(" in tab_text and ")" in tab_text:
                                            logger.success(f"Позиция найдена в списке (вкладка: '{tab_text}')")
                                            position_found = True
                                            await asyncio.sleep(2)
                                            break
                                except Exception:
                                    continue
                            
                            if position_found:
                                break
                            
                            # Способ 2: Проверяем наличие карточки позиции с BTC
                            position_card_selectors = [
                                'div.App-card:has-text("BTC")',
                                'div.Position-card-title:has-text("BTC")',
                                'div.Exchange-list-title:has-text("BTC")',
                            ]
                            
                            for card_selector in position_card_selectors:
                                try:
                                    position_card = page.locator(card_selector).first
                                    if await position_card.is_visible(timeout=2000):
                                        logger.success(f"Позиция найдена (найдена карточка позиции по селектору: {card_selector})")
                                        position_found = True
                                        await asyncio.sleep(2)
                                        break
                                except Exception:
                                    continue
                            
                            if position_found:
                                break
                            
                            # Способ 3: Проверяем таблицу позиций напрямую
                            try:
                                # Ищем строку в таблице с BTC
                                table_row = page.locator('tr:has-text("BTC")').first
                                if await table_row.is_visible(timeout=2000):
                                    logger.success("Позиция найдена в таблице")
                                    position_found = True
                                    await asyncio.sleep(2)
                                    break
                            except Exception:
                                pass
                            
                            # Способ 4: Проверяем наличие кнопки Close (если она есть, значит позиция открыта)
                            try:
                                close_button = page.locator('button:has-text("Close")').first
                                if await close_button.is_visible(timeout=2000):
                                    # Проверяем, что кнопка не disabled
                                    is_disabled = await close_button.get_attribute('disabled')
                                    if not is_disabled:
                                        logger.success("Позиция найдена (найдена активная кнопка Close)")
                                        position_found = True
                                        await asyncio.sleep(2)
                                        break
                            except Exception:
                                pass
                            
                            # Способ 5: Проверяем через JavaScript наличие элементов позиции
                            try:
                                has_position = await page.evaluate("""
                                    () => {
                                        // Проверяем вкладку Positions
                                        const positionsTab = Array.from(document.querySelectorAll('div.Tab-option')).find(
                                            el => el.textContent && el.textContent.includes('Positions') && el.textContent.includes('(')
                                        );
                                        if (positionsTab) return true;
                                        
                                        // Проверяем карточку позиции с BTC
                                        const allCards = Array.from(document.querySelectorAll('div.App-card, div.Position-card-title'));
                                        const positionCard = allCards.find(
                                            card => card.textContent && card.textContent.includes('BTC')
                                        );
                                        if (positionCard) return true;
                                        
                                        // Проверяем таблицу - ищем строку с BTC
                                        const allRows = Array.from(document.querySelectorAll('tr'));
                                        const tableRow = allRows.find(
                                            row => row.textContent && row.textContent.includes('BTC')
                                        );
                                        if (tableRow) return true;
                                        
                                        // Проверяем кнопку Close (если она активна, значит позиция есть)
                                        const closeBtn = Array.from(document.querySelectorAll('button')).find(
                                            btn => btn.textContent && btn.textContent.trim() === 'Close' && !btn.disabled
                                        );
                                        if (closeBtn) return true;
                                        
                                        // Проверяем наличие элемента с классом Exchange-list-title и BTC
                                        const exchangeTitle = Array.from(document.querySelectorAll('.Exchange-list-title')).find(
                                            el => el.textContent && el.textContent.includes('BTC')
                                        );
                                        if (exchangeTitle) return true;
                                        
                                        return false;
                                    }
                                """)
                                
                                if has_position:
                                    logger.success("Позиция найдена (через JavaScript проверку)")
                                    position_found = True
                                    await asyncio.sleep(2)
                                    break
                            except Exception as e:
                                logger.debug(f"Ошибка при JavaScript проверке: {e}")
                            
                            if not position_found:
                                logger.debug(f"Попытка {attempt + 1}/{max_position_attempts}: позиция не найдена, ждём...")
                                await asyncio.sleep(1)
                        except Exception as e:
                            logger.debug(f"Попытка {attempt + 1}/{max_position_attempts}: ошибка при поиске позиции: {e}")
                            await asyncio.sleep(1)
                            continue
                    
                    if position_found:
                        logger.info("Поиск кнопки 'Close' для закрытия позиции...")
                        
                        # Ищем кнопку "Close" и ждём её активности
                        close_button_clicked = False
                        max_close_attempts = 15
                        
                        for attempt in range(max_close_attempts):
                            try:
                                # Ищем кнопку "Close" в разных местах (приоритет таблице)
                                close_button_selectors = [
                                    'button.Exchange-list-action:has-text("Close")',
                                    'button.button.secondary.active-btn:has-text("Close")',
                                    'button.button.secondary:has-text("Close")',
                                    'button.active-btn:has-text("Close")',
                                    'button:has-text("Close")',
                                ]
                                
                                for selector in close_button_selectors:
                                    try:
                                        # Ищем все кнопки с этим селектором
                                        all_close_buttons = page.locator(selector)
                                        count = await all_close_buttons.count()
                                        
                                        for i in range(count):
                                            close_button = all_close_buttons.nth(i)
                                            if await close_button.is_visible(timeout=2000):
                                                # Проверяем, что кнопка не disabled
                                                is_disabled = await close_button.get_attribute('disabled')
                                                if is_disabled:
                                                    logger.debug(f"Попытка {attempt + 1}/{max_close_attempts}: кнопка 'Close' #{i} disabled, пробуем следующую...")
                                                    continue
                                                
                                                # Проверяем классы кнопки (должна быть активной)
                                                class_attr = await close_button.get_attribute('class')
                                                if class_attr and 'disabled' not in class_attr.lower():
                                                    # Проверяем, что это действительно кнопка Close для позиции
                                                    button_text = await close_button.text_content()
                                                    if button_text and "Close" in button_text.strip():
                                                        await close_button.click()
                                                        logger.success("Кнопка 'Close' нажата")
                                                        close_button_clicked = True
                                                        await asyncio.sleep(2)
                                                        break
                                        
                                        if close_button_clicked:
                                            break
                                    except Exception as e:
                                        logger.debug(f"Ошибка при поиске кнопки 'Close' по селектору {selector}: {e}")
                                        continue
                                
                                if close_button_clicked:
                                    break
                                
                                await asyncio.sleep(1)
                            except Exception as e:
                                logger.debug(f"Попытка {attempt + 1}/{max_close_attempts}: ошибка при поиске кнопки 'Close': {e}")
                                await asyncio.sleep(1)
                                continue
                        
                        if not close_button_clicked:
                            logger.warning("Не удалось найти активную кнопку 'Close'")
                        else:
                            logger.success("Кнопка 'Close' нажата, ожидание модального окна закрытия позиции...")
                            
                            # 12. Ждём появления модального окна закрытия позиции
                            close_modal_title = f"Close {direction} BTC"
                            logger.info(f"Ожидание модального окна '{close_modal_title}'...")
                            
                            close_modal_found = False
                            max_close_modal_attempts = 10
                            
                            for attempt in range(max_close_modal_attempts):
                                try:
                                    # Ищем модальное окно по заголовку
                                    close_modal_title_locator = page.locator(f'div.Modal-title:has-text("{close_modal_title}")')
                                    if await close_modal_title_locator.is_visible(timeout=2000):
                                        logger.success(f"Модальное окно '{close_modal_title}' найдено")
                                        close_modal_found = True
                                        await asyncio.sleep(1)
                                        break
                                except Exception as e:
                                    logger.debug(f"Попытка {attempt + 1}/{max_close_modal_attempts}: модальное окно не найдено, ждём...")
                                    await asyncio.sleep(1)
                                    continue
                            
                            if not close_modal_found:
                                # Пробуем найти модальное окно по классу и тексту "Close"
                                try:
                                    close_modal = page.locator('div.Modal-content:has-text("Close")').first
                                    if await close_modal.is_visible(timeout=5000):
                                        logger.success("Модальное окно закрытия найдено по классу")
                                        close_modal_found = True
                                except Exception as e:
                                    logger.debug(f"Модальное окно не найдено по классу: {e}")
                            
                            if not close_modal_found:
                                logger.warning("Модальное окно закрытия позиции не найдено")
                            else:
                                # 13. Нажимаем кнопку "Close" в модальном окне закрытия
                                logger.info("Поиск кнопки 'Close' в модальном окне закрытия позиции...")
                                close_modal_button_clicked = False
                                
                                close_modal_button_selectors = [
                                    'button.button.primary-action.w-full.center:has-text("Close")',
                                    'button.primary-action:has-text("Close")',
                                    'button.button:has-text("Close")',
                                    'button:has-text("Close")',
                                ]
                                
                                for selector in close_modal_button_selectors:
                                    try:
                                        close_modal_button = page.locator(selector).first
                                        if await close_modal_button.is_visible(timeout=5000):
                                            button_text = await close_modal_button.text_content()
                                            if button_text and "Close" in button_text.strip():
                                                await close_modal_button.click()
                                                logger.success("Кнопка 'Close' в модальном окне нажата")
                                                close_modal_button_clicked = True
                                                await asyncio.sleep(2)
                                                break
                                    except Exception as e:
                                        logger.debug(f"Не удалось найти кнопку 'Close' по селектору {selector}: {e}")
                                        continue
                                
                                if not close_modal_button_clicked:
                                    logger.warning("Не удалось нажать кнопку 'Close' в модальном окне")
                                else:
                                    # 14. Ждём открытия окна расширения кошелька для подтверждения закрытия
                                    logger.info("Ожидание открытия окна расширения кошелька для подтверждения закрытия...")
                                    extension_id = "acmacodkjbdgmoleebolmdjonilkdbch"
                                    close_extension_page = None
                                    
                                    # Ждём появления страницы расширения
                                    for attempt in range(15):
                                        for existing_page in context.pages:
                                            if existing_page.url.startswith(f"chrome-extension://{extension_id}/"):
                                                close_extension_page = existing_page
                                                break
                                        if close_extension_page:
                                            break
                                        await asyncio.sleep(1)
                                    
                                    if close_extension_page:
                                        logger.success("Окно расширения кошелька открыто для подтверждения закрытия")
                                        await asyncio.sleep(2)
                                        
                                        # 15. Нажимаем кнопку "Sign" в окне расширения
                                        logger.info("Поиск кнопки 'Sign' в окне расширения кошелька...")
                                        close_sign_button_clicked = False
                                        
                                        close_sign_button_selectors = [
                                            'button:has-text("Sign")',
                                            'span:has-text("Sign")',
                                            'div:has-text("Sign")',
                                            '[role="button"]:has-text("Sign")',
                                            'button.primary-action:has-text("Sign")',
                                        ]
                                        
                                        for selector in close_sign_button_selectors:
                                            try:
                                                close_sign_button = close_extension_page.locator(selector).first
                                                if await close_sign_button.is_visible(timeout=5000):
                                                    await close_sign_button.click()
                                                    logger.success("Кнопка 'Sign' нажата")
                                                    close_sign_button_clicked = True
                                                    await asyncio.sleep(2)
                                                    break
                                            except Exception as e:
                                                logger.debug(f"Не удалось найти кнопку 'Sign' по селектору {selector}: {e}")
                                                continue
                                        
                                        if not close_sign_button_clicked:
                                            logger.warning("Кнопка 'Sign' не найдена, пробуем альтернативные варианты...")
                                            try:
                                                all_buttons = close_extension_page.locator('button')
                                                count = await all_buttons.count()
                                                for i in range(count):
                                                    button = all_buttons.nth(i)
                                                    if await button.is_visible(timeout=2000):
                                                        button_text = await button.text_content()
                                                        if button_text and "Sign" in button_text:
                                                            await button.click()
                                                            logger.success(f"Кнопка 'Sign' нажата (найдена по тексту: '{button_text}')")
                                                            close_sign_button_clicked = True
                                                            await asyncio.sleep(2)
                                                            break
                                            except Exception as e:
                                                logger.debug(f"Ошибка при поиске кнопки 'Sign': {e}")
                                        
                                        # 16. Нажимаем кнопку "Confirm" в окне расширения
                                        logger.info("Поиск кнопки 'Confirm' в окне расширения кошелька...")
                                        await asyncio.sleep(1)
                                        
                                        close_confirm_button_clicked = False
                                        
                                        close_confirm_button_selectors = [
                                            'button:has-text("Confirm")',
                                            'span:has-text("Confirm")',
                                            'div:has-text("Confirm")',
                                            '[role="button"]:has-text("Confirm")',
                                            'button.primary-action:has-text("Confirm")',
                                        ]
                                        
                                        for selector in close_confirm_button_selectors:
                                            try:
                                                close_confirm_button = close_extension_page.locator(selector).first
                                                if await close_confirm_button.is_visible(timeout=5000):
                                                    await close_confirm_button.click()
                                                    logger.success("Кнопка 'Confirm' нажата")
                                                    close_confirm_button_clicked = True
                                                    await asyncio.sleep(2)
                                                    break
                                            except Exception as e:
                                                logger.debug(f"Не удалось найти кнопку 'Confirm' по селектору {selector}: {e}")
                                                continue
                                        
                                        if not close_confirm_button_clicked:
                                            logger.warning("Не удалось найти кнопку 'Confirm', пробуем альтернативные варианты...")
                                            try:
                                                all_buttons = close_extension_page.locator('button')
                                                count = await all_buttons.count()
                                                for i in range(count):
                                                    button = all_buttons.nth(i)
                                                    if await button.is_visible(timeout=2000):
                                                        button_text = await button.text_content()
                                                        if button_text and "Confirm" in button_text:
                                                            await button.click()
                                                            logger.success(f"Кнопка 'Confirm' нажата (найдена по тексту: '{button_text}')")
                                                            close_confirm_button_clicked = True
                                                            await asyncio.sleep(2)
                                                            break
                                            except Exception as e:
                                                logger.debug(f"Ошибка при поиске кнопки 'Confirm': {e}")
                                        
                                        if close_confirm_button_clicked:
                                            logger.success("Закрытие позиции подтверждено в кошельке")
                                            await asyncio.sleep(3)  # Даём время на обработку закрытия
                                        else:
                                            logger.warning("Кнопка 'Confirm' не найдена, возможно транзакция уже подтверждена")
                                    else:
                                        logger.warning("Окно расширения кошелька не найдено для подтверждения закрытия")
                                    
                                    logger.success("Позиция закрыта")
                    else:
                        logger.warning("Позиция не найдена в списке, возможно транзакция не прошла")
                else:
                    logger.warning("Не удалось вернуться на страницу SoneFi для проверки позиции")
                
                logger.success("Торговая операция выполнена успешно")
                return True

            finally:
                await playwright.stop()

        except Exception as e:
            logger.error(f"Ошибка при выполнении торговой операции: {e}")
            return False

    def _make_request(
        self, method: str, endpoint: str, data: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Выполняет HTTP запрос к AdsPower API.
        """
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
        
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.api_request_delay:
            sleep_time = self.api_request_delay - time_since_last_request
            logger.debug(f"Задержка {sleep_time:.2f} сек перед запросом к API AdsPower")
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
                    logger.debug(f"Ответ: статус {response.status_code}, тело: {response.text[:200]}")
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
                    logger.debug(f"Эндпоинт {endpoint_variant} вернул 404, пробуем следующий вариант")
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
                
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 404:
                        logger.debug(f"Эндпоинт {endpoint_variant} вернул 404, пробуем следующий вариант")
                        continue
                logger.debug(f"Ошибка для {endpoint_variant}: {e}, пробуем следующий вариант")
                continue
            except ValueError as e:
                raise

        raise requests.RequestException(
            f"Все варианты эндпоинтов вернули ошибку. Последняя ошибка: {last_error}"
        )

    def create_temp_profile(self, name: Optional[str] = None, use_proxy: bool = True) -> str:
        """
        Создает временный профиль Windows используя API v2.
        """
        if name is None:
            timestamp = int(time.time())
            unique_id = str(uuid.uuid4())[:8]
            name = f"temp_sonefi_{timestamp}_{unique_id}"

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
            profile_data["user_proxy_config"] = {
                "proxy_soft": "no_proxy",
            }
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
        """
        profile_id_value = profile_id or self.profile_id
        if not profile_id_value:
            raise ValueError("Не указан profile_id и нет созданного профиля")

        logger.info(f"Запуск браузера для профиля {profile_id_value}")

        browser_data = {
            "profile_id": profile_id_value,
        }

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
        """
        profile_id_value = profile_id or self.profile_id
        if not profile_id_value:
            logger.warning("Не указан profile_id для остановки браузера")
            return False

        logger.info(f"Остановка браузера для профиля {profile_id_value}")

        browser_data = {"profile_id": profile_id_value}

        try:
            result = self._make_request("POST", "/api/v2/browser-profile/stop", browser_data)
            logger.success(f"Браузер остановлен успешно")
            return True

        except Exception as e:
            logger.error(f"Ошибка при остановке браузера: {e}")
            return False

    def delete_cache(self, profile_id: Optional[str] = None) -> bool:
        """
        Очищает кэш профиля используя API v2.
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
                "image_file"
            ],
        }

        try:
            result = self._make_request("POST", "/api/v2/browser-profile/delete-cache", cache_data)
            logger.success(f"Кэш профиля {profile_id_value} очищен успешно")
            return True

        except Exception as e:
            logger.error(f"Ошибка при очистке кэша: {e}")
            return False

    def delete_profile(self, profile_id: Optional[str] = None, clear_cache: bool = True) -> bool:
        """
        Удаляет профиль используя API v2.
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
                result = self._make_request("POST", "/api/v2/browser-profile/delete", delete_data)
                logger.success(f"Профиль {profile_id_value} удален успешно")
                self.profile_id = None
                return True
            except ValueError as e:
                error_msg = str(e)
                if "profile_id" in error_msg.lower() or "Profile_id" in error_msg:
                    logger.debug(f"Вариант {list(delete_data.keys())[0]} не сработал: {e}, пробуем следующий")
                    continue
                raise
            except Exception as e:
                logger.error(f"Ошибка при удалении профиля: {e}")
                return False

        logger.error(f"Не удалось удалить профиль {profile_id_value} ни с одним вариантом параметра")
        return False

    def run_full_cycle(
        self, 
        key_index: int = 0, 
        wallet_password: str = "Password123", 
        use_proxy: bool = True,
        target_required: int = 10,
        check_progress: bool = True
    ) -> bool:
        """
        Выполняет полный цикл: проверка прогресса -> проверка баланса -> обмен при необходимости ->
        создание профиля -> открытие браузера -> импорт кошелька -> выполнение всех транзакций.

        Args:
            key_index: Индекс приватного ключа из keys.txt (по умолчанию 0)
            wallet_password: Пароль для кошелька (по умолчанию Password123)
            use_proxy: Использовать ли случайный прокси (по умолчанию True)
            target_required: Целевое количество транзакций (по умолчанию 10)
            check_progress: Проверять ли прогресс перед выполнением (по умолчанию True)

        Returns:
            True если цикл выполнен, False если кошелек уже выполнил задание
        """
        try:
            # Загружаем приватный ключ
            private_key = load_private_key(key_index=key_index)
            wallet_address = Web3.to_checksum_address(
                Web3().eth.account.from_key(private_key).address
            )
            logger.info(f"Адрес кошелька: {wallet_address}")
            
            # 1. Проверяем прогресс для вычисления количества транзакций (всегда)
            completed = 0
            transactions_needed = target_required
            
            try:
                profile = _fetch_portal_bonus_profile(wallet_address)
                completed, required = _extract_sonefi_progress(profile)
                
                target = int(target_required)
                done = min(int(completed), target)
                
                logger.info(f"{wallet_address} SoneFi {done}/{target}")
                
                if done >= target:
                    if check_progress:
                        logger.info(f"[SKIP] address={wallet_address} already {done}/{target}")
                        return False
                    else:
                        # Если check_progress=False, но кошелек уже выполнен, все равно пропускаем
                        logger.info(f"Кошелек уже выполнен {done}/{target}, пропускаем")
                        return False
                
                transactions_needed = target - done
                logger.info(f"Необходимо выполнить {transactions_needed} транзакций")
            except Exception as e:
                logger.warning(f"Ошибка при проверке прогресса: {e}, используем полное количество транзакций")
                transactions_needed = target_required
            
            # 2. Инициализация Web3 для работы с балансами
            w3 = Web3(Web3.HTTPProvider(RPC_URL_DEFAULT, request_kwargs={"timeout": 30}))
            if not w3.is_connected():
                raise RuntimeError("RPC недоступен (w3.is_connected() == False)")
            
            # 3. Проверка баланса USDC.e и обмен при необходимости
            logger.info("Проверка баланса USDC.e...")
            balance_usdce = get_usdce_balance(wallet_address, RPC_URL_DEFAULT)
            logger.info(f"Баланс USDC.e: {balance_usdce:.2f}")
            
            if balance_usdce < 10.01:
                logger.info("Баланс USDC.e недостаточен, проверяем баланс ETH...")
                
                # Получаем курс ETH/USDC.e
                try:
                    eth_usdce_rate = get_eth_usdce_rate(w3, QUOTER_ADDRESS)
                    logger.info(f"Курс ETH/USDC.e: {eth_usdce_rate:.2f}")
                except Exception as e:
                    logger.error(f"Не удалось получить курс ETH/USDC.e: {e}")
                    return False
                
                # Вычисляем сумму для обмена (10.49-10.99 USDC.e)
                swap_amount_usdce = round(random.uniform(10.49, 10.99), 2)
                logger.info(f"Планируемая сумма обмена: {swap_amount_usdce:.2f} USDC.e")
                
                # Вычисляем необходимую сумму ETH
                required_eth = calculate_required_eth_for_swap(
                    swap_amount_usdce, eth_usdce_rate, transactions_needed
                )
                logger.info(f"Необходимая сумма ETH: {required_eth:.6f}")
                
                # Проверяем баланс ETH
                balance_eth = get_eth_balance(wallet_address, RPC_URL_DEFAULT)
                logger.info(f"Баланс ETH: {balance_eth:.6f}")
                
                if balance_eth < required_eth:
                    logger.warning(f"Недостаточно ETH для обмена. Требуется: {required_eth:.6f}, доступно: {balance_eth:.6f}")
                    return False
                
                # Выполняем обмен
                logger.info("Выполнение обмена ETH на USDC.e...")
                swap_result = swap_eth_to_usdce(
                    w3, private_key, swap_amount_usdce, slippage=1.5
                )
                
                if not swap_result:
                    logger.error("Не удалось выполнить обмен ETH на USDC.e")
                    return False
                
                # Проверяем баланс после обмена
                time.sleep(2)
                balance_usdce = get_usdce_balance(wallet_address, RPC_URL_DEFAULT)
                logger.info(f"Баланс USDC.e после обмена: {balance_usdce:.2f}")
            
            # 4. Создание временного профиля Windows
            profile_id = self.create_temp_profile(use_proxy=use_proxy)

            # 5. Запуск браузера
            browser_info = self.start_browser(profile_id)

            # 6. Импорт кошелька и переход на SoneFi
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

                if not cdp_endpoint or not isinstance(cdp_endpoint, str):
                    logger.warning(
                        f"CDP endpoint не найден в browser_info. "
                        f"Доступные ключи: {list(browser_info.keys())}. "
                        f"Содержимое browser_info: {browser_info}. "
                        "Импорт кошелька пропущен."
                    )
                    return False
                
                time.sleep(5)  # Задержка для загрузки браузера
                
                wallet_address_imported = asyncio.run(
                    self._import_wallet_via_cdp(
                        cdp_endpoint=cdp_endpoint,
                        private_key=private_key,
                        password=wallet_password,
                    )
                )
                logger.success("Импорт кошелька завершён")
                
                # 7. Переход на страницу SoneFi
                logger.info("Переход на страницу SoneFi...")
                navigation_result = asyncio.run(
                    self._navigate_to_sonefi(cdp_endpoint=cdp_endpoint)
                )
                if not navigation_result:
                    logger.warning("Не удалось перейти на страницу SoneFi")
                    return False
                
                logger.success("Успешно перешли на страницу SoneFi")
                time.sleep(3)  # Дополнительная задержка для полной загрузки страницы
                
                # 8. Цикл выполнения транзакций
                successful_txs = 0
                for tx_num in range(1, transactions_needed + 1):
                    logger.info(f"=" * 60)
                    logger.info(f"Выполнение транзакции {tx_num}/{transactions_needed}")
                    logger.info(f"=" * 60)
                    
                    # Проверка прогресса через Portal API перед каждой транзакцией
                    try:
                        profile = _fetch_portal_bonus_profile(wallet_address)
                        completed, required = _extract_sonefi_progress(profile)
                        
                        target = int(target_required)
                        done = min(int(completed), target)
                        
                        logger.info(f"Текущий прогресс: {done}/{target}")
                        
                        # Если уже достигли цели - прекращаем выполнение
                        if done >= target:
                            logger.success(f"Достигнуто целевое количество транзакций {done}/{target}, прекращаем выполнение")
                            break
                        
                        # Обновляем количество оставшихся транзакций
                        remaining_txs = target - done
                        if remaining_txs < transactions_needed - tx_num + 1:
                            logger.info(f"Обновлено количество оставшихся транзакций: {remaining_txs}")
                    except Exception as e:
                        logger.warning(f"Ошибка при проверке прогресса перед транзакцией {tx_num}: {e}, продолжаем...")
                    
                    # Проверка баланса USDC.e перед каждой транзакцией
                    balance_usdce = get_usdce_balance(wallet_address, RPC_URL_DEFAULT)
                    logger.info(f"Баланс USDC.e перед транзакцией {tx_num}: {balance_usdce:.2f}")
                    
                    if balance_usdce < 10.01:
                        logger.warning(f"Баланс USDC.e недостаточен ({balance_usdce:.2f} < 10.01), выполняем обмен...")
                        
                        # Получаем курс
                        try:
                            eth_usdce_rate = get_eth_usdce_rate(w3, QUOTER_ADDRESS)
                        except Exception as e:
                            logger.error(f"Не удалось получить курс ETH/USDC.e: {e}")
                            continue
                        
                        # Вычисляем сумму для обмена
                        remaining_txs = transactions_needed - tx_num + 1
                        swap_amount_usdce = round(random.uniform(10.49, 10.99), 2)
                        required_eth = calculate_required_eth_for_swap(
                            swap_amount_usdce, eth_usdce_rate, remaining_txs
                        )
                        
                        # Проверяем баланс ETH
                        balance_eth = get_eth_balance(wallet_address, RPC_URL_DEFAULT)
                        if balance_eth < required_eth:
                            logger.warning(f"Недостаточно ETH для обмена. Требуется: {required_eth:.6f}, доступно: {balance_eth:.6f}")
                            continue
                        
                        # Выполняем обмен
                        swap_result = swap_eth_to_usdce(
                            w3, private_key, swap_amount_usdce, slippage=1.5
                        )
                        
                        if not swap_result:
                            logger.error("Не удалось выполнить обмен ETH на USDC.e")
                            continue
                        
                        # Проверяем баланс после обмена
                        time.sleep(2)
                        balance_usdce = get_usdce_balance(wallet_address, RPC_URL_DEFAULT)
                        logger.info(f"Баланс USDC.e после обмена: {balance_usdce:.2f}")
                    
                    # Выполнение торговой операции
                    logger.info(f"Выполнение торговой операции {tx_num}/{transactions_needed}...")
                    trade_result = asyncio.run(
                        self._execute_trade(cdp_endpoint=cdp_endpoint, wallet_address=wallet_address)
                    )
                    
                    if trade_result:
                        successful_txs += 1
                        logger.success(f"Транзакция {tx_num}/{transactions_needed} выполнена успешно")
                        
                        # Проверяем прогресс после успешной транзакции
                        try:
                            time.sleep(3)  # Даём время на обновление прогресса в Portal
                            profile = _fetch_portal_bonus_profile(wallet_address)
                            completed, required = _extract_sonefi_progress(profile)
                            
                            target = int(target_required)
                            done = min(int(completed), target)
                            
                            logger.info(f"Прогресс после транзакции {tx_num}: {done}/{target}")
                            
                            # Если достигли цели - прекращаем выполнение
                            if done >= target:
                                logger.success(f"Достигнуто целевое количество транзакций {done}/{target}, прекращаем выполнение")
                                break
                        except Exception as e:
                            logger.warning(f"Ошибка при проверке прогресса после транзакции {tx_num}: {e}, продолжаем...")
                    else:
                        logger.warning(f"Транзакция {tx_num}/{transactions_needed} не выполнена")
                    
                    # Задержка между транзакциями (кроме последней)
                    if tx_num < transactions_needed:
                        delay = random.randint(5, 15)
                        logger.info(f"Задержка {delay} секунд перед следующей транзакцией...")
                        time.sleep(delay)
                
                logger.success(f"Выполнено {successful_txs}/{transactions_needed} транзакций")
                
            except Exception as e:
                logger.error(f"Ошибка при импорте кошелька или выполнении транзакций: {e}")
                import traceback
                logger.debug(traceback.format_exc())

            # Ожидание перед закрытием браузера
            logger.info("Ожидание 5 секунд перед закрытием браузера...")
            time.sleep(5)

            # 9. Остановка браузера
            self.stop_browser(profile_id)

            # 10. Удаление профиля с полной очисткой кэша
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
    Продолжает выполнение пока все кошельки не достигнут целевого количества транзакций.
    """
    # Настройка логирования
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        level="INFO",
    )

    try:
        # Инициализация БД для квестов
        try:
            init_quests_database(QUESTS_DB_PATH)
            logger.debug("База данных квестов инициализирована")
        except Exception as e:
            logger.warning(f"Не удалось инициализировать БД квестов: {e}, продолжаем без БД")
        
        # Загрузка API ключа из файла
        api_key = load_adspower_api_key()
        logger.info("API ключ загружен из файла")

        # Загрузка всех ключей из keys.txt
        all_keys = load_all_keys()
        logger.info(f"Загружено ключей из keys.txt: {len(all_keys)}")
        
        # Создание экземпляра
        browser_manager = SoneFi(api_key=api_key)
        
        target_required = 10  # Целевое количество транзакций для SoneFi
        iteration = 0
        
        # Основной цикл: продолжаем пока есть кошельки, которым нужны транзакции
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
                logger.info(f"Обработка ключа {key_num}/{len(all_keys)} (индекс в файле: {key_index})")
                logger.info(f"=" * 60)
                
                try:
                    # Получаем адрес кошелька
                    private_key = load_private_key(key_index=key_index)
                    wallet_address = Web3.to_checksum_address(
                        Web3().eth.account.from_key(private_key).address
                    )
                    
                    # Проверяем БД перед запросом к Portal API
                    target = int(target_required)
                    if is_wallet_completed(wallet_address, "sonefi", QUESTS_DB_PATH):
                        logger.info(f"[SKIP DB] {wallet_address} SoneFi уже выполнен")
                        wallets_completed += 1
                        continue
                    
                    # Проверяем прогресс перед выполнением
                    try:
                        profile = _fetch_portal_bonus_profile(wallet_address)
                        completed, required = _extract_sonefi_progress(profile)
                        
                        done = min(int(completed), target)
                        
                        print(f"{wallet_address} SoneFi {done}/{target}")
                        
                        # Если уже достигли цели - сохраняем в БД и пропускаем
                        if done >= target:
                            mark_wallet_completed(wallet_address, "sonefi", done, target, QUESTS_DB_PATH)
                            logger.info(f"[SKIP] address={wallet_address} already {done}/{target}")
                            wallets_completed += 1
                            continue
                    except Exception as e:
                        # При ошибке проверки прогресса продолжаем выполнение
                        logger.warning(f"Ошибка при проверке прогресса: {e}, продолжаем выполнение...")
                    
                    # Выполняем цикл
                    cycle_result = browser_manager.run_full_cycle(
                        key_index=key_index,
                        target_required=target_required,
                        check_progress=False  # Уже проверили выше
                    )
                    
                    if cycle_result:
                        wallets_need_progress += 1
                        logger.success(f"Ключ {key_num}/{len(all_keys)} обработан успешно")
                        
                        # Задержка между обработкой разных ключей (только после успешной обработки)
                        if i < len(indices) - 1:
                            delay = random.randint(5, 15)
                            logger.info(f"Ожидание {delay} секунд перед обработкой следующего ключа...")
                            time.sleep(delay)
                    else:
                        wallets_completed += 1
                        logger.info(f"Ключ {key_num}/{len(all_keys)} уже выполнен или недостаточно баланса, пропущен")
                        # Задержка не применяется, если кошелек пропущен
                    
                except Exception as e:
                    logger.error(f"Ошибка при обработке ключа {key_num}/{len(all_keys)}: {e}")
                    wallets_need_progress += 1
                    # Задержка не применяется при ошибке
                    continue
            
            # Если все кошельки достигли цели - завершаем
            if wallets_need_progress == 0:
                logger.info("[COMPLETE] all wallets reached target {}/{}", target_required, target_required)
                print(f"\n✅ Все кошельки достигли цели {target_required}/{target_required} транзакций!")
                break
            
            # Логируем статистику итерации
            logger.info(
                "[ITERATION] #{} completed: {} wallets need progress, {} wallets completed",
                iteration,
                wallets_need_progress,
                wallets_completed,
            )
            print(f"Итерация #{iteration} завершена: {wallets_need_progress} кошельков нуждаются в прогрессе, {wallets_completed} завершены")

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
    run()
