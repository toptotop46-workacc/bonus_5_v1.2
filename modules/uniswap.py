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

# Позволяет запускать файл напрямую: `python modules/uniswap.py`
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
PORTAL_PROFILE_URL = "https://portal.soneium.org/api/profile/bonus-dapp"
PROXY_FILE = PROJECT_ROOT / "proxy.txt"

# === Конфиг RPC для Soneium ===
RPC_URL_DEFAULT = "https://soneium-rpc.publicnode.com"
CHAIN_ID = 1868


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


def _fetch_portal_bonus_profile(address: str, max_attempts: int = 30) -> list[dict[str, Any]]:
    """
    Берём СЛУЧАЙНЫЙ прокси из proxy.txt и запрашиваем:
      GET https://portal.soneium.org/api/profile/bonus-dapp?address=0x...
    """
    proxies_all = load_proxies()
    session = requests.Session()

    last_err: Exception | None = None

    attempts = max(1, int(max_attempts))
    # Если прокси есть — будем постоянно ротировать, НЕ используя прямое соединение
    pool: list[ProxyEntry] = proxies_all[:]
    random.shuffle(pool)

    for attempt in range(1, attempts + 1):
        p: Optional[ProxyEntry]
        proxies_cfg: Optional[dict[str, str]]

        if proxies_all:
            if not pool:
                pool = proxies_all[:]
                random.shuffle(pool)
            p = pool.pop()  # гарантированно другой, пока не исчерпаем пул
            proxies_cfg = {"http": p.http_url, "https": p.http_url}
        else:
            # если proxy.txt пуст — работаем без прокси
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

            # Иногда возможен rate limit / временные ошибки
            if r.status_code in (429, 500, 502, 503, 504):
                raise RuntimeError(f"portal http {r.status_code}")

            r.raise_for_status()
            data = r.json()
            if not isinstance(data, list):
                raise RuntimeError(f"Неожиданный формат ответа portal: {type(data)}")
            return data
        except Exception as e:
            last_err = e
            logger.info(
                "[PORTAL] attempt {}/{} proxy={} err={}",
                attempt,
                attempts,
                (p.safe_label if p else "none"),
                e,
            )
            # небольшой джиттер перед повтором
            time.sleep(random.uniform(0.4, 1.2))

    raise RuntimeError(f"Portal недоступен после {attempts} попыток (прокси ротировались): {last_err}")


def _extract_uniswap_progress(profile: list[dict[str, Any]]) -> tuple[int, int]:
    """
    Возвращает (completed, required) для квеста Uniswap.
    Ищем объект с id вида uniswap или uniswap_* (например, uniswap_5).
    """
    candidates: list[dict[str, Any]] = []
    for item in profile:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id", "")).lower()
        if item_id == "uniswap" or item_id.startswith("uniswap_"):
            candidates.append(item)

    if not candidates:
        raise RuntimeError("В ответе portal не найден квест uniswap или uniswap_*")

    # Сортируем по week (самый новый первым)
    candidates.sort(key=lambda x: int(x.get("week", 0) or 0), reverse=True)
    uniswap = candidates[0]
    quests = uniswap.get("quests") or []
    if not isinstance(quests, list) or not quests:
        raise RuntimeError("В uniswap* отсутствует quests[]")

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


def calculate_swap_amount(balance_eth: float, min_percent: float = 1.0, max_percent: float = 3.0) -> float:
    """
    Вычисляет случайную сумму для swap от min_percent до max_percent от баланса.
    
    Args:
        balance_eth: Баланс в ETH
        min_percent: Минимальный процент (по умолчанию 1.0)
        max_percent: Максимальный процент (по умолчанию 3.0)
    
    Returns:
        Случайная сумма в ETH
    """
    if balance_eth <= 0:
        raise ValueError(f"Баланс должен быть больше 0, получен: {balance_eth}")
    
    # Вычисляем случайный процент от min_percent до max_percent
    percent = random.uniform(min_percent, max_percent)
    
    # Вычисляем сумму
    amount = balance_eth * (percent / 100.0)
    
    return amount


def format_eth_amount(amount: float, max_decimals: int = 18) -> str:
    """
    Форматирует сумму ETH в обычный десятичный формат (без научной нотации).
    
    Args:
        amount: Сумма в ETH
        max_decimals: Максимальное количество знаков после запятой (по умолчанию 18)
    
    Returns:
        Отформатированная строка без научной нотации и лишних нулей
    """
    # Форматируем с достаточным количеством знаков, затем убираем лишние нули
    formatted = f"{amount:.{max_decimals}f}".rstrip('0').rstrip('.')
    return formatted


class Uniswap:
    """
    Класс для создания и управления временными браузерами через AdsPower Local API.
    Создает временный профиль Windows, открывает браузер, импортирует кошелек,
    открывает страницу Uniswap, затем закрывает браузер и полностью удаляет профиль с кэшем.
    """

    def __init__(
        self,
        api_key: str,
        api_port: int = 50325,
        base_url: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Инициализация класса Uniswap.

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
        self.session.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        })
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
                # ID расширения Rabby: acmacodkjbdgmoleebolmdjonilkdbch
                extension_id = "acmacodkjbdgmoleebolmdjonilkdbch"
                setup_url = f"chrome-extension://{extension_id}/index.html#/new-user/guide"
                
                page = None
                # Проверяем уже открытые страницы - ищем любую страницу расширения Rabby
                for existing_page in context.pages:
                    url = existing_page.url
                    # Проверяем, что это страница расширения Rabby
                    if extension_id in url or ("chrome-extension://" in url and "rabby" in url.lower()):
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
                
                return wallet_address

            finally:
                # В CDP-режиме не закрываем браузер/контекст — ими управляет AdsPower
                await playwright.stop()

        except Exception as e:
            logger.error(f"Ошибка при импорте кошелька: {e}")
            raise

    async def _execute_single_swap(
        self, page, context, swap_amount_eth: Optional[float] = None, swap_number: int = 1
    ) -> bool:
        """
        Выполняет одну swap-транзакцию на странице Uniswap.

        Args:
            page: Playwright page объект
            context: Playwright context объект
            swap_amount_eth: Сумма для swap в ETH (если указана, добавляется в URL как параметр value)
            swap_number: Номер текущей транзакции (для логирования)
        
        Returns:
            True если транзакция выполнена успешно, False в случае ошибки
        """
        try:
            logger.info(f"Выполнение swap-транзакции #{swap_number}...")
            
            # Переходим на страницу swap с параметрами (если это не первая транзакция, обновляем страницу)
            if swap_number > 1:
                logger.info(f"Обновление страницы swap для транзакции #{swap_number}...")
                swap_url = "https://app.uniswap.org/swap?chain=soneium&inputCurrency=NATIVE&outputCurrency=0xbA9986D2381edf1DA03B0B9c1f8b00dc4AacC369"
                
                if swap_amount_eth is not None and swap_amount_eth > 0:
                    swap_amount_formatted = format_eth_amount(swap_amount_eth)
                    swap_url += f"&value={swap_amount_formatted}&field=input"
                
                try:
                    await page.goto(swap_url, wait_until="domcontentloaded", timeout=60000)
                except Exception as e:
                    logger.debug(f"domcontentloaded не завершился, пробуем load: {e}")
                    try:
                        await page.goto(swap_url, wait_until="load", timeout=30000)
                    except Exception:
                        await page.goto(swap_url, timeout=30000)
                await asyncio.sleep(3)  # Даём время на загрузку страницы
            
            # Ожидаем появления и активации кнопки "Review"
            review_button_clicked = False
            try:
                logger.info(f"Ожидание кнопки 'Review' для транзакции #{swap_number}...")
                
                review_selectors = [
                    'button:has-text("Review")',
                    'button:has-text("Review"):not([disabled])',
                    '[role="button"]:has-text("Review")',
                ]
                
                # Ждём появления активной кнопки Review (не disabled)
                for attempt in range(30):  # Пробуем до 30 раз с интервалом 1 сек
                    for selector in review_selectors:
                        try:
                            review_button = await page.query_selector(selector)
                            if review_button:
                                is_disabled = await review_button.is_disabled()
                                is_visible = await review_button.is_visible()
                                
                                if not is_disabled and is_visible:
                                    await review_button.click()
                                    logger.success(f"Кнопка 'Review' нажата успешно (транзакция #{swap_number})")
                                    review_button_clicked = True
                                    await asyncio.sleep(2)  # Даём время на открытие модального окна
                                    break
                        except Exception:
                            continue
                    
                    if review_button_clicked:
                        break
                    
                    await asyncio.sleep(1)
                
                if not review_button_clicked:
                    logger.warning(f"Не удалось найти активную кнопку 'Review' для транзакции #{swap_number} за 30 секунд")
                    return False
            except Exception as e:
                logger.warning(f"Ошибка при поиске/клике кнопки 'Review' для транзакции #{swap_number}: {e}")
                return False
            
            # Ждём открытия модального окна и активной кнопки Swap
            swap_button_clicked = False
            try:
                logger.info(f"Ожидание модального окна и кнопки 'Swap' для транзакции #{swap_number}...")
                
                swap_selectors = [
                    'dialog button:has-text("Swap"):not([disabled])',
                    '[role="dialog"] button:has-text("Swap"):not([disabled])',
                    'dialog button:has-text("Swap")',
                    '[role="dialog"] button:has-text("Swap")',
                ]
                
                # Ждём появления активной кнопки Swap в модальном окне
                for swap_attempt in range(30):  # Пробуем до 30 раз с интервалом 1 сек
                    for swap_selector in swap_selectors:
                        try:
                            swap_button = await page.query_selector(swap_selector)
                            if swap_button:
                                is_disabled_swap = await swap_button.is_disabled()
                                is_visible_swap = await swap_button.is_visible()
                                
                                if not is_disabled_swap and is_visible_swap:
                                    # Проверяем, что кнопка находится в dialog
                                    is_in_dialog = await swap_button.evaluate("""
                                        (el) => {
                                            return el.closest('dialog, [role="dialog"]') !== null;
                                        }
                                    """)
                                    
                                    if is_in_dialog:
                                        await swap_button.click()
                                        logger.success(f"Кнопка 'Swap' в модальном окне нажата успешно (транзакция #{swap_number})")
                                        swap_button_clicked = True
                                        await asyncio.sleep(2)  # Даём время на открытие окна расширения кошелька
                                        break
                        except Exception:
                            continue
                    
                    if swap_button_clicked:
                        break
                    
                    await asyncio.sleep(1)
                
                if not swap_button_clicked:
                    logger.warning(f"Не удалось найти активную кнопку 'Swap' для транзакции #{swap_number} за 30 секунд")
                    return False
            except Exception as e:
                logger.warning(f"Ошибка при поиске/клике кнопки 'Swap' для транзакции #{swap_number}: {e}")
                return False
            
            # Обрабатываем подтверждение транзакции в расширении кошелька
            try:
                logger.info(f"Ожидание окна расширения кошелька для подтверждения транзакции #{swap_number}...")
                
                extension_id = "acmacodkjbdgmoleebolmdjonilkdbch"
                extension_page = None
                
                # Ждём появления страницы расширения (может открыться с задержкой)
                for attempt in range(15):  # Пробуем до 15 раз с интервалом 0.5 сек
                    for existing_page in context.pages:
                        if existing_page.url.startswith(f"chrome-extension://{extension_id}/"):
                            extension_page = existing_page
                            break
                    if extension_page:
                        break
                    await asyncio.sleep(0.5)
                
                if extension_page:
                    logger.info(f"Страница расширения кошелька найдена для подтверждения транзакции #{swap_number}")
                    
                    # Шаг 1: Ищем и нажимаем кнопку "Sign"
                    sign_clicked = False
                    try:
                        logger.info(f"Ожидание кнопки 'Sign' для транзакции #{swap_number}...")
                        sign_selectors = [
                            'button:has-text("Sign")',
                            'span:has-text("Sign")',
                            '[role="button"]:has-text("Sign")',
                            'button:has-text("Sign"):not([disabled])',
                        ]
                        
                        for sign_attempt in range(20):  # Пробуем до 20 раз
                            for selector in sign_selectors:
                                try:
                                    sign_button = await extension_page.wait_for_selector(selector, timeout=2000)
                                    if sign_button:
                                        is_disabled_sign = await sign_button.is_disabled()
                                        is_visible_sign = await sign_button.is_visible()
                                        
                                        if not is_disabled_sign and is_visible_sign:
                                            await sign_button.click()
                                            logger.success(f"Кнопка 'Sign' нажата успешно (транзакция #{swap_number})")
                                            sign_clicked = True
                                            await asyncio.sleep(1)  # Даём время на обработку
                                            break
                                except Exception:
                                    continue
                            
                            if sign_clicked:
                                break
                            await asyncio.sleep(0.5)
                        
                        if not sign_clicked:
                            logger.warning(f"Не удалось найти активную кнопку 'Sign' для транзакции #{swap_number} за 10 секунд")
                    except Exception as e:
                        logger.warning(f"Ошибка при поиске/клике кнопки 'Sign' для транзакции #{swap_number}: {e}")
                    
                    # Шаг 2: Ищем и нажимаем кнопку "Confirm"
                    if sign_clicked:
                        confirm_clicked = False
                        try:
                            logger.info(f"Ожидание кнопки 'Confirm' для транзакции #{swap_number}...")
                            await asyncio.sleep(1)  # Небольшая задержка после Sign
                            
                            confirm_selectors = [
                                'button:has-text("Confirm")',
                                'span:has-text("Confirm")',
                                '[role="button"]:has-text("Confirm")',
                                'button:has-text("Confirm"):not([disabled])',
                            ]
                            
                            for confirm_attempt in range(20):  # Пробуем до 20 раз
                                for selector in confirm_selectors:
                                    try:
                                        confirm_button = await extension_page.wait_for_selector(selector, timeout=2000)
                                        if confirm_button:
                                            is_disabled_confirm = await confirm_button.is_disabled()
                                            is_visible_confirm = await confirm_button.is_visible()
                                            
                                            if not is_disabled_confirm and is_visible_confirm:
                                                await confirm_button.click()
                                                logger.success(f"Кнопка 'Confirm' нажата успешно (транзакция #{swap_number})")
                                                confirm_clicked = True
                                                await asyncio.sleep(2)  # Даём время на обработку транзакции
                                                break
                                    except Exception:
                                        continue
                                
                                if confirm_clicked:
                                    break
                                await asyncio.sleep(0.5)
                            
                            if not confirm_clicked:
                                logger.warning(f"Не удалось найти активную кнопку 'Confirm' для транзакции #{swap_number} за 10 секунд")
                        except Exception as e:
                            logger.warning(f"Ошибка при поиске/клике кнопки 'Confirm' для транзакции #{swap_number}: {e}")
                    else:
                        logger.warning(f"Кнопка 'Sign' не была нажата для транзакции #{swap_number}, пропускаем 'Confirm'")
                else:
                    logger.warning(f"Страница расширения кошелька не найдена для подтверждения транзакции #{swap_number}")
            except Exception as e:
                logger.warning(f"Ошибка при обработке подтверждения транзакции #{swap_number} в расширении: {e}")
            
            logger.success(f"Swap-транзакция #{swap_number} завершена")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка при выполнении swap-транзакции #{swap_number}: {e}")
            return False

    async def _open_uniswap_via_cdp(
        self, cdp_endpoint: str, swap_amount_eth: Optional[float] = None, num_swaps: int = 1, wallet_address: Optional[str] = None
    ) -> bool:
        """
        Закрывает страницы расширения кошелька и открывает страницу Uniswap.
        Выполняет указанное количество swap-транзакций.

        Args:
            cdp_endpoint: CDP endpoint (например, ws://127.0.0.1:9222)
            swap_amount_eth: Сумма для swap в ETH (если указана, добавляется в URL как параметр value)
            num_swaps: Количество swap-транзакций для выполнения (по умолчанию 1)
            wallet_address: Адрес кошелька для получения баланса перед каждой транзакцией (опционально)
        
        Returns:
            True если успешно открыли страницу и выполнили транзакции, False в случае ошибки
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

                # Переходим на страницу Uniswap
                logger.info("Переход на страницу https://app.uniswap.org/?lng=en-US")
                try:
                    await page.goto("https://app.uniswap.org/?lng=en-US", wait_until="domcontentloaded", timeout=60000)
                except Exception as e:
                    # Если networkidle не сработал, пробуем load
                    logger.debug(f"domcontentloaded не завершился, пробуем load: {e}")
                    try:
                        await page.goto("https://app.uniswap.org/?lng=en-US", wait_until="load", timeout=30000)
                    except Exception:
                        # Если и load не сработал, просто ждём
                        logger.debug("Ожидание загрузки страницы...")
                        await page.goto("https://app.uniswap.org/?lng=en-US", timeout=30000)
                
                await asyncio.sleep(3)  # Даём время на загрузку страницы
                
                # Ищем и нажимаем кнопку Connect в header (не в форме swap)
                connect_button_clicked = False
                
                try:
                    logger.info("Ожидание кнопки 'Connect' в header...")
                    
                    # Сначала ждём загрузки страницы
                    await asyncio.sleep(2)
                    
                    # Ищем все элементы с текстом "Connect"
                    connect_elements = await page.query_selector_all('button:has-text("Connect"), span:has-text("Connect"), [role="button"]:has-text("Connect")')
                    
                    if connect_elements:
                        # Выбираем элемент, который находится выше на странице (в header)
                        best_element = None
                        min_y = float('inf')
                        
                        for element in connect_elements:
                            try:
                                is_visible = await element.is_visible()
                                if is_visible:
                                    box = await element.bounding_box()
                                    if box and box['y'] < min_y:
                                        min_y = box['y']
                                        best_element = element
                            except Exception:
                                continue
                        
                        if best_element and min_y < 300:  # Кнопка Connect должна быть в верхней части
                            await best_element.click()
                            logger.success("Кнопка 'Connect' в header нажата успешно")
                            connect_button_clicked = True
                        else:
                            logger.warning("Не найдена подходящая кнопка 'Connect' в header")
                    else:
                        # Если не нашли через query_selector_all, пробуем через wait_for_selector
                        connect_selectors = [
                            'header button:has-text("Connect")',
                            'header span:has-text("Connect")',
                            'nav button:has-text("Connect")',
                            'nav span:has-text("Connect")',
                            'button:has-text("Connect")',
                            'span.font_button:has-text("Connect")',
                        ]
                        
                        for selector in connect_selectors:
                            try:
                                element = await page.wait_for_selector(selector, timeout=5000)
                                if element:
                                    box = await element.bounding_box()
                                    if box and box['y'] < 300:  # Проверяем, что кнопка в верхней части
                                        await element.click()
                                        logger.success(f"Кнопка 'Connect' нажата успешно (селектор: {selector})")
                                        connect_button_clicked = True
                                        break
                            except Exception:
                                continue
                        
                        if not connect_button_clicked:
                            logger.warning("Не удалось найти кнопку 'Connect' в header")
                except Exception as e:
                    logger.warning(f"Ошибка при поиске кнопки 'Connect': {e}")
                
                # Если кнопка Connect была нажата, ждём модальное окно и нажимаем "Rabby Wallet"
                if connect_button_clicked:
                    await asyncio.sleep(2)  # Даём время на открытие модального окна
                    
                    # Ищем и нажимаем "Rabby Wallet" в модальном окне
                    rabby_wallet_clicked = False
                    
                    try:
                        logger.info("Ожидание элемента 'Rabby Wallet' в модальном окне...")
                        # Пробуем разные селекторы для Rabby Wallet
                        # Сначала пробуем найти img элемент с alt="Rabby Wallet" или родительский кликабельный элемент
                        rabby_selectors = [
                            'img[alt="Rabby Wallet"]',  # Прямой поиск img элемента
                            'button:has(img[alt="Rabby Wallet"])',  # button содержащий img
                            'div:has(img[alt="Rabby Wallet"])',  # div содержащий img
                            '[role="button"]:has(img[alt="Rabby Wallet"])',  # элемент с role="button"
                            'span:has-text("Rabby Wallet")',  # span с текстом (старый вариант)
                            'div:has-text("Rabby Wallet")',  # div с текстом (старый вариант)
                            'span.font_body:has-text("Rabby Wallet")',  # span с классом font_body
                            '[class*="font_body"]:has-text("Rabby Wallet")',  # элемент с классом содержащим font_body
                        ]
                        
                        for selector in rabby_selectors:
                            try:
                                element = await page.wait_for_selector(selector, timeout=5000)
                                if element:
                                    # Проверяем, что элемент видим
                                    is_visible = await element.is_visible()
                                    if is_visible:
                                        # Если это img, используем JavaScript для клика на родительский кликабельный элемент
                                        tag_name = await element.evaluate("(el) => el.tagName.toLowerCase()")
                                        if tag_name == "img":
                                            # Пробуем найти и кликнуть на родительский кликабельный элемент через JavaScript
                                            clicked = await element.evaluate("""
                                                (el) => {
                                                    const parent = el.closest('button, div[role="button"], div[onclick], a, [role="button"]');
                                                    if (parent) {
                                                        parent.click();
                                                        return true;
                                                    }
                                                    // Если родитель не найден, пробуем кликнуть на сам img
                                                    el.click();
                                                    return true;
                                                }
                                            """)
                                            if clicked:
                                                logger.success("Элемент 'Rabby Wallet' нажат успешно (img элемент)")
                                                rabby_wallet_clicked = True
                                                await asyncio.sleep(0.5)  # Небольшая задержка после клика
                                                break
                                        else:
                                            await element.click()
                                            logger.success("Элемент 'Rabby Wallet' нажат успешно")
                                            rabby_wallet_clicked = True
                                            await asyncio.sleep(0.5)  # Небольшая задержка после клика
                                            break
                            except Exception as e:
                                logger.debug(f"Селектор {selector} не сработал: {e}")
                                continue
                        
                        if not rabby_wallet_clicked:
                            logger.warning("Не удалось найти элемент 'Rabby Wallet'")
                    except Exception as e:
                        logger.warning(f"Ошибка при поиске элемента 'Rabby Wallet': {e}")
                    
                    # Если "Rabby Wallet" была нажата, обрабатываем расширение кошелька
                    if rabby_wallet_clicked:
                        await asyncio.sleep(2)  # Даём время на открытие расширения
                        
                        # Ищем страницу расширения кошелька
                        extension_id = "acmacodkjbdgmoleebolmdjonilkdbch"
                        extension_page = None
                        
                        # Ждём появления страницы расширения (может открыться с задержкой)
                        for attempt in range(10):  # Пробуем до 10 раз с интервалом 0.5 сек
                            for existing_page in context.pages:
                                if existing_page.url.startswith(f"chrome-extension://{extension_id}/"):
                                    extension_page = existing_page
                                    break
                            if extension_page:
                                break
                            await asyncio.sleep(0.5)
                        
                        if extension_page:
                            logger.info("Страница расширения кошелька найдена")
                            
                            # Кликаем на кнопку "Connect" в расширении
                            connect_clicked = False
                            
                            try:
                                logger.info("Ожидание кнопки 'Connect' в расширении...")
                                # Пробуем разные селекторы для кнопки Connect в расширении
                                connect_selectors = [
                                    'span:has-text("Connect")',
                                    'button:has-text("Connect")',
                                    '[role="button"]:has-text("Connect")',
                                ]
                                
                                for selector in connect_selectors:
                                    try:
                                        await extension_page.wait_for_selector(selector, timeout=30000)
                                        await extension_page.click(selector)
                                        logger.success("Кнопка 'Connect' в расширении нажата успешно")
                                        connect_clicked = True
                                        await asyncio.sleep(1)  # Даём время на обработку
                                        break
                                    except Exception:
                                        continue
                                
                                if not connect_clicked:
                                    logger.warning("Не удалось найти кнопку 'Connect' в расширении")
                            except Exception as e:
                                logger.warning(f"Ошибка при поиске кнопки 'Connect' в расширении: {e}")
                        else:
                            logger.warning("Страница расширения кошелька не найдена")
                        
                        # Перезагружаем страницу с параметром ?lng=en-US после подключения кошелька
                        # чтобы избежать переключения языка на язык прокси
                        if connect_clicked or rabby_wallet_clicked:
                            await asyncio.sleep(2)  # Даём время на завершение подключения
                            logger.info("Перезагрузка страницы с параметром ?lng=en-US...")
                            try:
                                await page.goto("https://app.uniswap.org/?lng=en-US", wait_until="domcontentloaded", timeout=60000)
                            except Exception as e:
                                logger.debug(f"domcontentloaded не завершился, пробуем load: {e}")
                                try:
                                    await page.goto("https://app.uniswap.org/?lng=en-US", wait_until="load", timeout=30000)
                                except Exception:
                                    logger.debug("Ожидание загрузки страницы...")
                                    await page.goto("https://app.uniswap.org/?lng=en-US", timeout=30000)
                            await asyncio.sleep(2)  # Даём время на загрузку страницы
                            logger.success("Страница с английским языком загружена")
                            
                            # Переходим на страницу swap с параметрами
                            logger.info("Переход на страницу swap с параметрами...")
                            
                            # Формируем URL для swap
                            swap_url = "https://app.uniswap.org/swap?chain=soneium&inputCurrency=NATIVE&outputCurrency=0xbA9986D2381edf1DA03B0B9c1f8b00dc4AacC369"
                            
                            # Если указана сумма для swap, добавляем параметры value и field
                            if swap_amount_eth is not None and swap_amount_eth > 0:
                                # Форматируем сумму в обычный десятичный формат (без научной нотации)
                                swap_amount_formatted = format_eth_amount(swap_amount_eth)
                                swap_url += f"&value={swap_amount_formatted}&field=input"
                                logger.info(f"Используется сумма для swap: {swap_amount_formatted} ETH")
                            
                            try:
                                await page.goto(
                                    swap_url,
                                    wait_until="domcontentloaded",
                                    timeout=60000
                                )
                            except Exception as e:
                                logger.debug(f"domcontentloaded не завершился, пробуем load: {e}")
                                try:
                                    await page.goto(
                                        swap_url,
                                        wait_until="load",
                                        timeout=30000
                                    )
                                except Exception:
                                    logger.debug("Ожидание загрузки страницы swap...")
                                    await page.goto(
                                        swap_url,
                                        timeout=30000
                                    )
                            await asyncio.sleep(2)  # Даём время на загрузку страницы swap
                            logger.success("Страница swap загружена успешно")
                            
                            # Проверяем наличие языкового элемента и кликаем по нему, если он есть
                            try:
                                logger.info("Проверка наличия языкового элемента...")
                                
                                # Ищем ссылку с параметром lng= в href (языковой переключатель)
                                # Используем более специфичные селекторы на основе структуры HTML
                                language_selectors = [
                                    'a.sc-fhHczv[href*="lng="]',
                                    'a.kkFQlk[href*="lng="]',
                                    'span.font_body a[href*="lng="]',
                                    'a[href*="lng="][data-discover="true"]',
                                    'a[href*="&lng="]',
                                    'a[href*="?lng="]',
                                ]
                                
                                language_found = False
                                
                                for lang_selector in language_selectors:
                                    try:
                                        # Ищем все ссылки с языковым параметром
                                        links = await page.query_selector_all(lang_selector)
                                        for link in links:
                                            try:
                                                href = await link.get_attribute('href')
                                                if href and ('lng=' in href or '&lng=' in href):
                                                    # Проверяем, что это ссылка на swap с нужными параметрами
                                                    if 'swap' in href.lower() and 'chain=soneium' in href:
                                                        is_visible = await link.is_visible()
                                                        if is_visible:
                                                            # Получаем текст перед кликом
                                                            language_text = await link.inner_text()
                                                            language_text = language_text.strip() if language_text else 'язык'
                                                            logger.info(f"Найден языковой элемент: {language_text}")
                                                            
                                                            # Используем JavaScript клик для надежности (избегаем ошибки "Element is not attached to the DOM")
                                                            try:
                                                                await link.evaluate("(el) => el.click()")
                                                                logger.success(f"Клик по языковому элементу выполнен: {language_text}")
                                                                language_found = True
                                                                await asyncio.sleep(1)  # Даём время на переключение языка
                                                                break
                                                            except Exception as click_error:
                                                                # Если JavaScript клик не сработал, пробуем обычный клик
                                                                try:
                                                                    await link.click()
                                                                    logger.success(f"Клик по языковому элементу выполнен (обычный клик): {language_text}")
                                                                    language_found = True
                                                                    await asyncio.sleep(1)
                                                                    break
                                                                except Exception:
                                                                    logger.warning(f"Не удалось кликнуть по языковому элементу: {click_error}")
                                                                    continue
                                            except Exception:
                                                continue
                                        
                                        if language_found:
                                            break
                                    except Exception:
                                        continue
                                
                                if not language_found:
                                    logger.debug("Языковой элемент не найден, продолжаем без переключения языка")
                            except Exception as e:
                                logger.warning(f"Ошибка при проверке языкового элемента: {e}, продолжаем...")
                            
                            # Выполняем указанное количество swap-транзакций
                            logger.info(f"Начинаем выполнение {num_swaps} swap-транзакций...")
                            successful_swaps = 0
                            
                            for swap_num in range(1, num_swaps + 1):
                                if swap_num > 1:
                                    # Пауза между транзакциями (10-30 секунд)
                                    delay = random.uniform(10, 30)
                                    logger.info(f"Пауза {delay:.1f} секунд перед следующей транзакцией...")
                                    await asyncio.sleep(delay)
                                
                                # Для каждой транзакции пересчитываем сумму на основе текущего баланса
                                current_swap_amount = swap_amount_eth
                                if wallet_address:
                                    try:
                                        # Получаем текущий баланс кошелька
                                        current_balance = get_eth_balance(wallet_address)
                                        logger.info(f"Текущий баланс ETH для транзакции #{swap_num}: {current_balance} ETH")
                                        
                                        if current_balance > 0:
                                            # Вычисляем новую сумму для swap (1-3% от текущего баланса)
                                            current_swap_amount = calculate_swap_amount(current_balance, min_percent=1.0, max_percent=3.0)
                                            swap_amount_formatted = format_eth_amount(current_swap_amount)
                                            logger.info(f"Вычислена сумма для swap #{swap_num}: {swap_amount_formatted} ETH ({current_swap_amount/current_balance*100:.2f}% от баланса)")
                                        else:
                                            logger.warning(f"Баланс ETH равен 0 для транзакции #{swap_num}, используем исходную сумму")
                                            current_swap_amount = swap_amount_eth
                                    except Exception as e:
                                        logger.warning(f"Не удалось получить баланс для транзакции #{swap_num}: {e}, используем исходную сумму")
                                        current_swap_amount = swap_amount_eth
                                
                                swap_result = await self._execute_single_swap(
                                    page=page,
                                    context=context,
                                    swap_amount_eth=current_swap_amount,
                                    swap_number=swap_num
                                )
                                
                                if swap_result:
                                    successful_swaps += 1
                                    logger.success(f"Транзакция #{swap_num}/{num_swaps} выполнена успешно")
                                else:
                                    logger.warning(f"Транзакция #{swap_num}/{num_swaps} не выполнена")
                            
                            logger.info(f"Выполнено swap-транзакций: {successful_swaps}/{num_swaps}")
                
                logger.success("Страница Uniswap открыта успешно")
                return True

            finally:
                # В CDP-режиме не закрываем браузер/контекст — ими управляет AdsPower
                await playwright.stop()

        except Exception as e:
            logger.error(f"Ошибка при открытии Uniswap: {e}")
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
        # Если эндпоинт уже v2, используем его как есть
        if "/api/v2/" in endpoint:
            endpoints_to_try = [endpoint]
        else:
            # Пробуем v2 версию в первую очередь, затем другие варианты
            endpoints_to_try = [
                endpoint.replace("/api/v1/", "/api/v2/"),  # v2 версия
                endpoint,  # Оригинальный
                endpoint.replace("/api/v1/", "/v1/"),  # Без /api/
                endpoint.replace("/api/v1/", "/api/"),  # Без /v1/
            ]
        
        # Убираем дубликаты
        endpoints_to_try = list(dict.fromkeys(endpoints_to_try))
        
        # Добавляем задержку между запросами к API AdsPower для избежания rate limit
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.api_request_delay:
            sleep_time = self.api_request_delay - time_since_last_request
            logger.debug(f"Задержка {sleep_time:.2f} сек перед запросом к API AdsPower (rate limiting)")
            time.sleep(sleep_time)
        
        last_error = None
        request_made = False  # Флаг, что был сделан HTTP запрос
        
        for endpoint_variant in endpoints_to_try:
            url = f"{self.base_url}{endpoint_variant}"
            
            # API ключ всегда передается через query параметры
            # Согласно документации AdsPower, API ключ передается как query параметр
            params = {"api_key": self.api_key}
            
            try:
                # Все запросы используют query параметры для API ключа
                if method.upper() == "GET":
                    response = self.session.get(url, params=params, timeout=self.timeout)
                elif method.upper() == "POST":
                    # Для POST: API ключ в query параметрах, данные в теле
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

                # Обновляем время последнего запроса после каждого HTTP запроса
                request_made = True
                self.last_request_time = time.time()

                # Если получили 404, пробуем следующий вариант эндпоинта
                if response.status_code == 404:
                    last_error = f"404 Not Found: {url}"
                    logger.debug(f"Эндпоинт {endpoint_variant} вернул 404, пробуем следующий вариант")
                    continue

                response.raise_for_status()
                result = response.json()

                # Проверяем статус ответа API
                if result.get("code") != 0:
                    error_msg = result.get("msg", "Неизвестная ошибка API")
                    raise ValueError(f"Ошибка API: {error_msg}")

                logger.debug(f"Успешный запрос к {endpoint_variant}")
                return result

            except requests.RequestException as e:
                last_error = str(e)
                # Если был сделан HTTP запрос, обновляем время (даже при ошибке)
                if not request_made:
                    request_made = True
                    self.last_request_time = time.time()
                
                # Проверяем статус код, если response доступен
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 404:
                        # Продолжаем пробовать другие варианты
                        logger.debug(f"Эндпоинт {endpoint_variant} вернул 404, пробуем следующий вариант")
                        continue
                # Для других ошибок - пробуем следующий вариант
                logger.debug(f"Ошибка для {endpoint_variant}: {e}, пробуем следующий вариант")
                continue
            except ValueError as e:
                # Ошибка API (не 404) - возвращаем сразу
                raise

        # Если все варианты не сработали
        raise requests.RequestException(
            f"Все варианты эндпоинтов вернули ошибку. Последняя ошибка: {last_error}"
        )

    def create_temp_profile(self, name: Optional[str] = None, use_proxy: bool = True) -> str:
        """
        Создает временный профиль Windows используя API v2.

        Args:
            name: Имя профиля (если не указано, генерируется автоматически)
            use_proxy: Использовать ли случайный прокси (по умолчанию True).
                       Если True, используется proxyid="random" для случайного выбора сохраненного прокси.
                       Если False, используется user_proxy_config с no_proxy.

        Returns:
            ID созданного профиля
        """
        if name is None:
            # Генерируем уникальное имя с timestamp и UUID
            timestamp = int(time.time())
            unique_id = str(uuid.uuid4())[:8]
            name = f"temp_windows_{timestamp}_{unique_id}"

        logger.info(f"Создание временного профиля Windows: {name}")

        # Конфигурация для профиля Windows согласно API v2
        # Обязательные параметры: group_id (0 = Ungrouped) и fingerprint_config
        # Либо user_proxy_config, либо proxyid обязательны
        profile_data = {
            "name": name,
            "group_id": "0",  # 0 = Ungrouped (обязательный параметр)
            "fingerprint_config": {
                "automatic_timezone": "1",  # Автоматический часовой пояс
                "language": ["en-US", "en"],  # Язык: всегда английский (en-US - основной, en - дополнительный)
                "webrtc": "disabled",  # Отключить WebRTC
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        }
        
        # Настройка прокси согласно документации API v2
        # proxyid может быть ID прокси или "random" для случайного выбора сохраненного прокси
        if use_proxy:
            profile_data["proxyid"] = "random"  # Случайный прокси из сохраненных
            logger.info("Использование случайного прокси из сохраненных")
        else:
            profile_data["user_proxy_config"] = {
                "proxy_soft": "no_proxy",  # Без прокси
            }
            logger.info("Профиль создается без прокси")

        try:
            # Используем API v2 эндпоинт
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
            Данные о запущенном браузере (WebDriver endpoint, debugger_address и т.д.)
        """
        profile_id_value = profile_id or self.profile_id
        if not profile_id_value:
            raise ValueError("Не указан profile_id и нет созданного профиля")

        logger.info(f"Запуск браузера для профиля {profile_id_value}")

        # API v2 использует profile_id (не user_id)
        browser_data = {
            "profile_id": profile_id_value,
        }

        try:
            # Используем API v2 эндпоинт
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

        # API v2 использует profile_id (не user_id)
        browser_data = {"profile_id": profile_id_value}

        try:
            # Используем API v2 эндпоинт
            result = self._make_request("POST", "/api/v2/browser-profile/stop", browser_data)
            logger.success(f"Браузер остановлен успешно")
            return True

        except Exception as e:
            logger.error(f"Ошибка при остановке браузера: {e}")
            return False

    def delete_cache(self, profile_id: Optional[str] = None) -> bool:
        """
        Очищает кэш профиля используя API v2.
        Согласно документации, для безопасности нужно убедиться, что браузер закрыт.

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

        # API v2 использует profile_id (массив) и type (массив типов кэша)
        # Очищаем все типы кэша: local_storage, indexeddb, extension_cache, cookie, history, image_file
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
        Если clear_cache=True, сначала очищает кэш, затем удаляет профиль.

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

        # Если нужно очистить кэш, делаем это перед удалением
        if clear_cache:
            self.delete_cache(profile_id_value)

        logger.info(f"Удаление профиля {profile_id_value}")

        # Пробуем оба варианта: сначала profile_id (с маленькой буквы), затем Profile_id
        # Ошибка говорит "profile_id is required", значит API ожидает маленькую букву
        delete_data_variants = [
            {"profile_id": [profile_id_value]},  # С маленькой буквы (как в ошибке)
            {"Profile_id": [profile_id_value]},  # С заглавной буквы (как в документации)
        ]

        for delete_data in delete_data_variants:
            try:
                logger.debug(f"Пробуем удалить профиль с параметром: {list(delete_data.keys())[0]}")
                # Используем API v2 эндпоинт
                result = self._make_request("POST", "/api/v2/browser-profile/delete", delete_data)
                logger.success(f"Профиль {profile_id_value} удален успешно")
                self.profile_id = None  # Сбрасываем сохраненный ID
                return True
            except ValueError as e:
                # Если это ошибка API (не 404), пробуем следующий вариант
                error_msg = str(e)
                if "profile_id" in error_msg.lower() or "Profile_id" in error_msg:
                    logger.debug(f"Вариант {list(delete_data.keys())[0]} не сработал: {e}, пробуем следующий")
                    continue
                # Другая ошибка - возвращаем
                raise
            except Exception as e:
                logger.error(f"Ошибка при удалении профиля: {e}")
                return False

        # Если все варианты не сработали
        logger.error(f"Не удалось удалить профиль {profile_id_value} ни с одним вариантом параметра")
        return False

    def run_full_cycle(
        self, wait_time: int = 3, import_wallet: bool = True, key_index: int = 0, wallet_password: str = "Password123", use_proxy: bool = True, target_required: int = 20, check_progress: bool = True
    ) -> bool:
        """
        Выполняет полный цикл: создание профиля -> открытие браузера -> импорт кошелька -> 
        открытие страницы Uniswap -> ожидание -> закрытие -> удаление.

        Args:
            wait_time: Время ожидания в секундах (по умолчанию 3)
            import_wallet: Импортировать ли кошелек Rabby (по умолчанию True)
            key_index: Индекс приватного ключа из keys.txt (по умолчанию 0)
            wallet_password: Пароль для кошелька (по умолчанию Password123)
            use_proxy: Использовать ли случайный прокси (по умолчанию True)
            target_required: Целевое количество транзакций (по умолчанию 20)
            check_progress: Проверять ли прогресс перед выполнением (по умолчанию True)

        Returns:
            True если цикл выполнен, False если кошелек уже выполнил задание
        """
        try:
            # Проверяем прогресс перед выполнением (если включено)
            if check_progress:
                try:
                    # Загружаем приватный ключ для получения адреса
                    private_key = load_private_key(key_index=key_index)
                    wallet_address = Web3.to_checksum_address(
                        Web3().eth.account.from_key(private_key).address
                    )
                    
                    # Получаем профиль через Portal API
                    profile = _fetch_portal_bonus_profile(wallet_address)
                    completed, required = _extract_uniswap_progress(profile)
                    
                    target = int(target_required)
                    done = min(int(completed), target)
                    
                    logger.info(f"{wallet_address} Uniswap {done}/{target}")
                    
                    # Если уже достигли цели - пропускаем
                    if done >= target:
                        logger.info(f"[SKIP] address={wallet_address} already {done}/{target}")
                        return False
                except Exception as e:
                    # При ошибке проверки прогресса продолжаем выполнение
                    logger.warning(f"Ошибка при проверке прогресса: {e}, продолжаем выполнение...")

            # 1. Создание временного профиля Windows
            profile_id = self.create_temp_profile(use_proxy=use_proxy)

            # 2. Запуск браузера
            browser_info = self.start_browser(profile_id)

            # 3. Импорт кошелька (если включен)
            if import_wallet:
                try:
                    # Получаем CDP endpoint из browser_info
                    cdp_endpoint = None
                    
                    # Пробуем получить по структуре из документации: data['data']['ws']['puppeteer']
                    ws_data = browser_info.get("ws")
                    if isinstance(ws_data, dict):
                        cdp_endpoint = ws_data.get("puppeteer")
                    
                    # Если не нашли, пробуем альтернативные варианты
                    if not cdp_endpoint:
                        # Пробуем напрямую из browser_info
                        cdp_endpoint = (
                            browser_info.get("ws_endpoint")
                            or browser_info.get("ws_endpoint_driver")
                            or browser_info.get("puppeteer")
                            or browser_info.get("debugger_address")
                        )
                        
                        # Если это словарь, извлекаем puppeteer endpoint
                        if isinstance(cdp_endpoint, dict):
                            cdp_endpoint = cdp_endpoint.get("puppeteer") or cdp_endpoint.get("ws")
                    
                    # Последняя попытка: ищем любой ключ со строкой, начинающейся с ws://
                    if not cdp_endpoint:
                        for key, value in browser_info.items():
                            if isinstance(value, str) and value.startswith("ws://"):
                                cdp_endpoint = value
                                break
                            elif isinstance(value, dict):
                                # Если значение - словарь, пробуем извлечь puppeteer
                                cdp_endpoint = value.get("puppeteer") or value.get("ws")
                                if cdp_endpoint:
                                    break

                    if cdp_endpoint and isinstance(cdp_endpoint, str):
                        # Загружаем приватный ключ
                        private_key = load_private_key(key_index=key_index)
                        
                        # Вычисляем адрес кошелька из приватного ключа через web3
                        wallet_address = Web3.to_checksum_address(
                            Web3().eth.account.from_key(private_key).address
                        )
                        logger.info(f"Адрес кошелька: {wallet_address}")
                        
                        # Получаем баланс ETH и вычисляем сумму для swap (1-3% от баланса)
                        swap_amount_eth = None
                        try:
                            balance_eth = get_eth_balance(wallet_address)
                            logger.info(f"Баланс ETH: {balance_eth} ETH")
                            
                            if balance_eth > 0:
                                swap_amount_eth = calculate_swap_amount(balance_eth, min_percent=1.0, max_percent=3.0)
                                swap_amount_formatted = format_eth_amount(swap_amount_eth)
                                logger.info(f"Вычислена сумма для swap: {swap_amount_formatted} ETH ({swap_amount_eth/balance_eth*100:.2f}% от баланса)")
                            else:
                                logger.warning("Баланс ETH равен 0, swap будет выполнен без указания суммы")
                        except Exception as e:
                            logger.warning(f"Не удалось получить баланс или вычислить сумму для swap: {e}, продолжаем без суммы")
                        
                        # Небольшая задержка для полной загрузки браузера и расширения
                        time.sleep(5)
                        
                        # Импортируем кошелек через CDP
                        wallet_address_imported = asyncio.run(
                            self._import_wallet_via_cdp(
                                cdp_endpoint=cdp_endpoint,
                                private_key=private_key,
                                password=wallet_password,
                            )
                        )
                        logger.success("Импорт кошелька завершён")
                        
                        # Генерируем случайное количество swap-транзакций от 1 до 3
                        num_swaps = random.randint(1, 3)
                        logger.info(f"Будет выполнено {num_swaps} swap-транзакций")
                        
                        # Открываем страницу Uniswap с вычисленной суммой
                        logger.info("Открытие страницы Uniswap...")
                        uniswap_result = asyncio.run(
                            self._open_uniswap_via_cdp(
                                cdp_endpoint=cdp_endpoint,
                                swap_amount_eth=swap_amount_eth,
                                num_swaps=num_swaps,
                                wallet_address=wallet_address
                            )
                        )
                        if uniswap_result:
                            logger.success("Страница Uniswap открыта успешно")
                        else:
                            logger.warning("Не удалось открыть страницу Uniswap, но продолжаем выполнение цикла")
                    else:
                        logger.warning(
                            f"CDP endpoint не найден в browser_info. "
                            f"Тип endpoint: {type(cdp_endpoint)}, значение: {cdp_endpoint}. "
                            f"Доступные ключи: {list(browser_info.keys())}. "
                            f"Содержимое browser_info: {browser_info}. "
                            "Импорт кошелька пропущен."
                        )
                except Exception as e:
                    logger.error(f"Ошибка при импорте кошелька: {e}")
                    # Продолжаем выполнение даже если импорт не удался
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
            # Пытаемся очистить ресурсы при прерывании
            if self.profile_id:
                try:
                    self.stop_browser(self.profile_id)
                    self.delete_profile(self.profile_id, clear_cache=True)
                except Exception:
                    pass
            return False
        except Exception as e:
            logger.error(f"Ошибка при выполнении цикла: {e}")
            # Пытаемся очистить ресурсы при ошибке
            if self.profile_id:
                try:
                    self.stop_browser(self.profile_id)
                    self.delete_profile(self.profile_id, clear_cache=True)
                except Exception:
                    pass
            # При ошибке возвращаем True, чтобы попробовать еще раз в следующей итерации
            return True


def run() -> None:
    """
    Главная функция для запуска модуля из main.py.
    Загружает API ключ из файла и выполняет полный цикл для всех ключей в случайном порядке.
    Продолжает выполнение пока все кошельки не достигнут целевого количества транзакций.
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
        browser_manager = Uniswap(api_key=api_key)
        
        target_required = 20  # Целевое количество транзакций для Uniswap
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
                    if is_wallet_completed(wallet_address, "uniswap", QUESTS_DB_PATH):
                        logger.info(f"[SKIP DB] {wallet_address} Uniswap уже выполнен")
                        wallets_completed += 1
                        continue
                    
                    # Проверяем прогресс перед выполнением
                    try:
                        profile = _fetch_portal_bonus_profile(wallet_address)
                        completed, _required = _extract_uniswap_progress(profile)
                        
                        # Используем фиксированный target_required = 20
                        target = int(target_required)
                        done = min(int(completed), target)
                        
                        print(f"{wallet_address} Uniswap {done}/{target}")
                        
                        # Если уже достигли цели - сохраняем в БД и пропускаем
                        if done >= target:
                            mark_wallet_completed(wallet_address, "uniswap", done, target, QUESTS_DB_PATH)
                            logger.info(f"[SKIP] address={wallet_address} already {done}/{target}")
                            wallets_completed += 1
                            continue
                    except Exception as e:
                        # При ошибке проверки прогресса продолжаем выполнение
                        logger.warning(f"Ошибка при проверке прогресса: {e}, продолжаем выполнение...")
                    
                    # Выполняем цикл
                    cycle_result = browser_manager.run_full_cycle(
                        wait_time=3, 
                        key_index=key_index,
                        target_required=target,
                        check_progress=False  # Уже проверили выше
                    )
                    
                    if cycle_result:
                        wallets_need_progress += 1
                        logger.success(f"Ключ {key_num}/{len(all_keys)} обработан успешно")
                    else:
                        wallets_completed += 1
                        logger.info(f"Ключ {key_num}/{len(all_keys)} уже выполнен, пропущен")
                    
                except Exception as e:
                    logger.error(f"Ошибка при обработке ключа {key_num}/{len(all_keys)}: {e}")
                    # При ошибке считаем, что нужен прогресс, чтобы попробовать еще раз
                    wallets_need_progress += 1
                    continue
                
                # Небольшая задержка между обработкой разных ключей
                if i < len(indices) - 1:
                    delay = random.randint(5, 15)
                    logger.info(f"Ожидание {delay} секунд перед обработкой следующего ключа...")
                    time.sleep(delay)
            
            # Если все кошельки достигли цели - завершаем
            if wallets_need_progress == 0:
                logger.info("[COMPLETE] all wallets reached target")
                print(f"\n✅ Все кошельки достигли цели!")
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
    # CLI-аргументы убраны по запросу пользователя.
    # Запуск: `python modules/uniswap.py` или через `python main.py`.
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        level="INFO",
    )
    run()

