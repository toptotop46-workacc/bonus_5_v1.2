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

# Позволяет запускать файл напрямую: `python modules/CashOrCrash.py`
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


def _extract_cashorcrash_progress(profile: list[dict[str, Any]]) -> tuple[int, int]:
    """
    Возвращает (completed, required) для квеста Cash or Crash.
    Ищем объект с id вида intraversegames_* (например, intraversegames_5).
    """
    candidates: list[dict[str, Any]] = []
    for item in profile:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id", "")).lower()
        if item_id.startswith("intraversegames"):
            candidates.append(item)

    if not candidates:
        raise RuntimeError("В ответе portal не найден квест intraversegames_*")

    # Сортируем по week (самый новый первым)
    candidates.sort(key=lambda x: int(x.get("week", 0) or 0), reverse=True)
    coc = candidates[0]
    quests = coc.get("quests") or []
    if not isinstance(quests, list) or not quests:
        raise RuntimeError("В intraversegames_* отсутствует quests[]")

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


class CashOrCrash:
    """
    Класс для создания и управления временными браузерами через AdsPower Local API.
    Создает временный профиль Windows, открывает браузер, ждет указанное время,
    затем закрывает браузер и полностью удаляет профиль с кэшем.
    """

    def __init__(
        self,
        api_key: str,
        api_port: int = 50325,
        base_url: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Инициализация класса CashOrCrash.

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

        # Проверка статуса API убрана - проверка будет при реальных запросах

    async def _import_wallet_via_cdp(
        self, cdp_endpoint: str, private_key: str, password: str = "Password123"
    ) -> Optional[str]:
        """
        Импортирует кошелек Rabby через CDP endpoint.
        Предполагается, что страница расширения уже открыта автоматически.

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

    async def _connect_to_soneium_via_cdp(self, cdp_endpoint: str) -> Optional[bool]:
        """
        Закрывает страницы расширения кошелька, переходит на страницу Soneium и нажимает кнопку Sign In.

        Args:
            cdp_endpoint: CDP endpoint (например, ws://127.0.0.1:9222)
        
        Returns:
            True если успешно подключились, None если обнаружено "Out of IP Games", False в случае ошибки
        """
        import re  # Для извлечения значения коэффициента из текста
        import random  # Для выбора случайной кнопки
        
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

                # Переходим на страницу Soneium
                logger.info("Переход на страницу https://soneium.superstake.fun/")
                await page.goto("https://soneium.superstake.fun/", wait_until="networkidle", timeout=60000)
                await asyncio.sleep(3)  # Даём время на загрузку страницы
                
                # Проверяем и закрываем модальное окно "Enter Referral Code" если оно есть
                try:
                    # Ищем модальное окно с текстом "Enter Referral Code"
                    referral_modal_selector = 'text=/Enter Referral Code/i'
                    modal_visible = await page.locator(referral_modal_selector).is_visible(timeout=2000)
                    
                    if modal_visible:
                        logger.info("Обнаружено модальное окно 'Enter Referral Code', закрываем...")
                        # Ищем кнопку закрытия (обычно это крестик или кнопка Close)
                        close_button_selectors = [
                            'button[aria-label="Close"]',
                            'button:has-text("Close")',
                            'button[aria-label="close"]',
                            '[role="button"][aria-label*="close" i]',
                            'button:has([aria-label*="close" i])',
                        ]
                        
                        modal_closed = False
                        for close_selector in close_button_selectors:
                            try:
                                close_button = page.locator(close_selector).first
                                if await close_button.is_visible(timeout=1000):
                                    await close_button.click()
                                    logger.success("Модальное окно 'Enter Referral Code' закрыто")
                                    modal_closed = True
                                    await asyncio.sleep(1)
                                    break
                            except Exception:
                                continue
                        
                        # Если не нашли кнопку закрытия, пробуем нажать Escape
                        if not modal_closed:
                            try:
                                await page.keyboard.press("Escape")
                                logger.success("Модальное окно 'Enter Referral Code' закрыто через Escape")
                                await asyncio.sleep(1)
                            except Exception as e:
                                logger.debug(f"Не удалось закрыть модальное окно через Escape: {e}")
                except Exception as e:
                    # Модальное окно не найдено - это нормально
                    logger.debug(f"Модальное окно 'Enter Referral Code' не найдено: {e}")

                # Ищем и нажимаем кнопку Sign In
                # Используем селектор по data-slot="button" и тексту "Sign In"
                sign_in_button_selector = 'button[data-slot="button"]:has-text("Sign In")'
                sign_in_clicked = False
                
                try:
                    logger.info("Ожидание кнопки Sign In...")
                    await page.wait_for_selector(sign_in_button_selector, timeout=30000)
                    await page.click(sign_in_button_selector)
                    logger.success("Кнопка Sign In нажата успешно")
                    sign_in_clicked = True
                except Exception as e:
                    # Пробуем альтернативный селектор - только по data-slot
                    logger.debug(f"Не удалось найти кнопку по селектору {sign_in_button_selector}, пробуем альтернативный: {e}")
                    try:
                        # Ищем кнопку с data-slot="button" и текстом "Sign In" (регистронезависимо)
                        sign_in_text_selector = 'button[data-slot="button"]:has-text("Sign In"), button[data-slot="button"]:has-text("sign in")'
                        await page.wait_for_selector(sign_in_text_selector, timeout=10000)
                        await page.click(sign_in_text_selector)
                        logger.success("Кнопка Sign In нажата успешно (через альтернативный селектор)")
                        sign_in_clicked = True
                    except Exception as e2:
                        # Последняя попытка - просто по тексту
                        logger.debug(f"Не удалось найти кнопку по альтернативному селектору, пробуем по тексту: {e2}")
                        try:
                            text_selector = 'button:has-text("Sign In"), button:has-text("sign in")'
                            await page.wait_for_selector(text_selector, timeout=10000)
                            await page.click(text_selector)
                            logger.success("Кнопка Sign In нажата успешно (через текстовый селектор)")
                            sign_in_clicked = True
                        except Exception as e3:
                            logger.error(f"Не удалось найти кнопку Sign In: {e3}")
                            return False
                
                # Если кнопка Sign In была нажата, ждём модальное окно и нажимаем "Other wallets"
                if sign_in_clicked:
                    await asyncio.sleep(2)  # Даём время на открытие модального окна
                    
                    # Ищем и нажимаем "Other wallets" в модальном окне
                    # Селектор: div с классом Grow-sc-681ff332-0 hbBdoF и текстом "Other wallets"
                    other_wallets_selector = 'div.Grow-sc-681ff332-0.hbBdoF:has-text("Other wallets")'
                    other_wallets_clicked = False
                    
                    try:
                        logger.info("Ожидание элемента 'Other wallets' в модальном окне...")
                        await page.wait_for_selector(other_wallets_selector, timeout=30000)
                        await page.click(other_wallets_selector)
                        logger.success("Элемент 'Other wallets' нажат успешно")
                        other_wallets_clicked = True
                    except Exception as e:
                        # Пробуем альтернативные селекторы
                        logger.debug(f"Не удалось найти элемент по селектору {other_wallets_selector}, пробуем альтернативные: {e}")
                        try:
                            # Пробуем по классу без полного совпадения
                            class_selector = 'div.hbBdoF:has-text("Other wallets")'
                            await page.wait_for_selector(class_selector, timeout=10000)
                            await page.click(class_selector)
                            logger.success("Элемент 'Other wallets' нажат успешно (через альтернативный селектор класса)")
                            other_wallets_clicked = True
                        except Exception as e2:
                            try:
                                # Пробуем просто по тексту
                                text_selector = 'div:has-text("Other wallets")'
                                await page.wait_for_selector(text_selector, timeout=10000)
                                await page.click(text_selector)
                                logger.success("Элемент 'Other wallets' нажат успешно (через текстовый селектор)")
                                other_wallets_clicked = True
                            except Exception as e3:
                                logger.error(f"Не удалось найти элемент 'Other wallets': {e3}")
                                return False
                    
                    # Если "Other wallets" была нажата, ждём и нажимаем "Rabby Wallet"
                    if other_wallets_clicked:
                        await asyncio.sleep(1)  # Даём время на обновление списка кошельков
                        
                        # Ищем и нажимаем "Rabby Wallet"
                        # Селектор: span с классом WalletName-sc-3f4ad407-5 cQWVxL и текстом "Rabby Wallet"
                        rabby_wallet_selector = 'span.WalletName-sc-3f4ad407-5.cQWVxL:has-text("Rabby Wallet")'
                        rabby_wallet_clicked = False
                        
                        try:
                            logger.info("Ожидание элемента 'Rabby Wallet'...")
                            await page.wait_for_selector(rabby_wallet_selector, timeout=30000)
                            await page.click(rabby_wallet_selector)
                            logger.success("Элемент 'Rabby Wallet' нажат успешно")
                            rabby_wallet_clicked = True
                        except Exception as e:
                            # Пробуем альтернативные селекторы
                            logger.debug(f"Не удалось найти элемент по селектору {rabby_wallet_selector}, пробуем альтернативные: {e}")
                            try:
                                # Пробуем по классу без полного совпадения
                                class_selector = 'span.cQWVxL:has-text("Rabby Wallet")'
                                await page.wait_for_selector(class_selector, timeout=10000)
                                await page.click(class_selector)
                                logger.success("Элемент 'Rabby Wallet' нажат успешно (через альтернативный селектор класса)")
                                rabby_wallet_clicked = True
                            except Exception as e2:
                                try:
                                    # Пробуем просто по тексту
                                    text_selector = 'span:has-text("Rabby Wallet")'
                                    await page.wait_for_selector(text_selector, timeout=10000)
                                    await page.click(text_selector)
                                    logger.success("Элемент 'Rabby Wallet' нажат успешно (через текстовый селектор)")
                                    rabby_wallet_clicked = True
                                except Exception as e3:
                                    logger.error(f"Не удалось найти элемент 'Rabby Wallet': {e3}")
                                    return False
                        
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
                            
                            if not extension_page:
                                logger.warning("Страница расширения кошелька не найдена, пробуем найти любую страницу расширения")
                                # Пробуем найти любую страницу расширения
                                for existing_page in context.pages:
                                    if existing_page.url.startswith("chrome-extension://"):
                                        extension_page = existing_page
                                        logger.info(f"Найдена страница расширения: {extension_page.url}")
                                        break
                            
                            if extension_page:
                                logger.info("Обработка расширения кошелька...")
                                
                                # Кликаем на "Ignore all"
                                ignore_all_selector = 'span.underline.text-13.font-medium.cursor-pointer:has-text("Ignore all")'
                                
                                try:
                                    logger.info("Ожидание элемента 'Ignore all' в расширении...")
                                    await extension_page.wait_for_selector(ignore_all_selector, timeout=30000)
                                    await extension_page.click(ignore_all_selector)
                                    logger.success("Элемент 'Ignore all' нажат успешно")
                                    await asyncio.sleep(1)  # Сон 1 секунда как указано
                                except Exception as e:
                                    # Пробуем альтернативные селекторы
                                    logger.debug(f"Не удалось найти элемент по селектору {ignore_all_selector}, пробуем альтернативные: {e}")
                                    try:
                                        # Пробуем по классу и тексту без полного совпадения
                                        class_selector = 'span.underline:has-text("Ignore all")'
                                        await extension_page.wait_for_selector(class_selector, timeout=10000)
                                        await extension_page.click(class_selector)
                                        logger.success("Элемент 'Ignore all' нажат успешно (через альтернативный селектор)")
                                        await asyncio.sleep(1)
                                    except Exception as e2:
                                        try:
                                            # Пробуем просто по тексту
                                            text_selector = 'span:has-text("Ignore all")'
                                            await extension_page.wait_for_selector(text_selector, timeout=10000)
                                            await extension_page.click(text_selector)
                                            logger.success("Элемент 'Ignore all' нажат успешно (через текстовый селектор)")
                                            await asyncio.sleep(1)
                                        except Exception as e3:
                                            logger.warning(f"Не удалось найти элемент 'Ignore all': {e3}, продолжаем...")
                                
                                # Кликаем на "Connect"
                                connect_selector = 'span:has-text("Connect")'
                                
                                try:
                                    logger.info("Ожидание элемента 'Connect' в расширении...")
                                    await extension_page.wait_for_selector(connect_selector, timeout=30000)
                                    await extension_page.click(connect_selector)
                                    logger.success("Элемент 'Connect' нажат успешно")
                                    await asyncio.sleep(2)  # Даём время на открытие нового окна расширения
                                    
                                    # Ждём появления нового окна расширения для подписи
                                    logger.info("Ожидание нового окна расширения для подписи...")
                                    sign_page = None
                                    
                                    # Ждём появления новой страницы расширения (может открыться с задержкой)
                                    for attempt in range(15):  # Пробуем до 15 раз с интервалом 0.5 сек
                                        for existing_page in context.pages:
                                            # Ищем страницу расширения, которая отличается от текущей
                                            if (existing_page.url.startswith(f"chrome-extension://{extension_id}/") 
                                                and existing_page != extension_page):
                                                sign_page = existing_page
                                                break
                                        if sign_page:
                                            break
                                        await asyncio.sleep(0.5)
                                    
                                    if not sign_page:
                                        logger.warning("Новое окно расширения не найдено, пробуем найти любую новую страницу расширения")
                                        # Пробуем найти любую новую страницу расширения
                                        for existing_page in context.pages:
                                            if (existing_page.url.startswith("chrome-extension://") 
                                                and existing_page != extension_page):
                                                sign_page = existing_page
                                                break
                                    
                                    if sign_page:
                                        logger.info("Обработка окна подписи...")
                                        
                                        # Кликаем на кнопку "Sign"
                                        sign_button_selector = 'button:has-text("Sign")'
                                        
                                        try:
                                            logger.info("Ожидание кнопки 'Sign' в окне подписи...")
                                            await sign_page.wait_for_selector(sign_button_selector, timeout=30000)
                                            await sign_page.click(sign_button_selector)
                                            logger.success("Кнопка 'Sign' нажата успешно")
                                            await asyncio.sleep(1)  # Даём время на обработку
                                        except Exception as e:
                                            # Пробуем альтернативные селекторы
                                            logger.debug(f"Не удалось найти кнопку по селектору {sign_button_selector}, пробуем альтернативные: {e}")
                                            try:
                                                # Пробуем регистронезависимо
                                                sign_text_selector = 'button:has-text("Sign"), button:has-text("sign")'
                                                await sign_page.wait_for_selector(sign_text_selector, timeout=10000)
                                                await sign_page.click(sign_text_selector)
                                                logger.success("Кнопка 'Sign' нажата успешно (через альтернативный селектор)")
                                                await asyncio.sleep(1)
                                            except Exception as e2:
                                                logger.warning(f"Не удалось найти кнопку 'Sign': {e2}, продолжаем...")
                                        
                                        # Кликаем на кнопку "Confirm"
                                        confirm_button_selector = 'button:has-text("Confirm")'
                                        confirm_clicked = False
                                        
                                        try:
                                            logger.info("Ожидание кнопки 'Confirm' в окне подписи...")
                                            await sign_page.wait_for_selector(confirm_button_selector, timeout=30000)
                                            await sign_page.click(confirm_button_selector)
                                            logger.success("Кнопка 'Confirm' нажата успешно")
                                            confirm_clicked = True
                                        except Exception as e:
                                            # Пробуем альтернативные селекторы
                                            logger.debug(f"Не удалось найти кнопку по селектору {confirm_button_selector}, пробуем альтернативные: {e}")
                                            try:
                                                # Пробуем регистронезависимо
                                                confirm_text_selector = 'button:has-text("Confirm"), button:has-text("confirm")'
                                                await sign_page.wait_for_selector(confirm_text_selector, timeout=10000)
                                                await sign_page.click(confirm_text_selector)
                                                logger.success("Кнопка 'Confirm' нажата успешно (через альтернативный селектор)")
                                                confirm_clicked = True
                                            except Exception as e2:
                                                logger.error(f"Не удалось найти кнопку 'Confirm': {e2}")
                                                return False
                                        
                                        # Если "Confirm" была нажата, возвращаемся на основную страницу и кликаем "Play with IP"
                                        if confirm_clicked:
                                            await asyncio.sleep(2)  # Даём время на обработку подписи и возврат на основную страницу
                                            
                                            # Возвращаемся на основную страницу Soneium
                                            logger.info("Возврат на основную страницу Soneium...")
                                            await page.goto("https://soneium.superstake.fun/", wait_until="networkidle", timeout=60000)
                                            await asyncio.sleep(2)  # Даём время на загрузку страницы
                                            
                                            # Проверяем и закрываем модальное окно "Enter Referral Code" если оно есть
                                            try:
                                                # Ищем модальное окно с текстом "Enter Referral Code"
                                                referral_modal_selector = 'text=/Enter Referral Code/i'
                                                modal_visible = await page.locator(referral_modal_selector).is_visible(timeout=2000)
                                                
                                                if modal_visible:
                                                    logger.info("Обнаружено модальное окно 'Enter Referral Code', закрываем...")
                                                    # Ищем кнопку закрытия (обычно это крестик или кнопка Close)
                                                    close_button_selectors = [
                                                        'button[aria-label="Close"]',
                                                        'button:has-text("Close")',
                                                        'button[aria-label="close"]',
                                                        '[role="button"][aria-label*="close" i]',
                                                        'button:has([aria-label*="close" i])',
                                                    ]
                                                    
                                                    modal_closed = False
                                                    for close_selector in close_button_selectors:
                                                        try:
                                                            close_button = page.locator(close_selector).first
                                                            if await close_button.is_visible(timeout=1000):
                                                                await close_button.click()
                                                                logger.success("Модальное окно 'Enter Referral Code' закрыто")
                                                                modal_closed = True
                                                                await asyncio.sleep(1)
                                                                break
                                                        except Exception:
                                                            continue
                                                    
                                                    # Если не нашли кнопку закрытия, пробуем нажать Escape
                                                    if not modal_closed:
                                                        try:
                                                            await page.keyboard.press("Escape")
                                                            logger.success("Модальное окно 'Enter Referral Code' закрыто через Escape")
                                                            await asyncio.sleep(1)
                                                        except Exception as e:
                                                            logger.debug(f"Не удалось закрыть модальное окно через Escape: {e}")
                                            except Exception as e:
                                                # Модальное окно не найдено - это нормально
                                                logger.debug(f"Модальное окно 'Enter Referral Code' не найдено: {e}")
                                            
                                            # Цикл игры: продолжаем играть до появления "Out of IP Games"
                                            game_round = 0
                                            failed_attempts = 0  # Счетчик неудачных попыток подряд
                                            max_failed_attempts = 5  # Максимальное количество неудачных попыток подряд
                                            max_game_rounds = 10  # Максимальное количество раундов для защиты от зацикливания
                                            
                                            while True:
                                                game_round += 1
                                                logger.info(f"Начало раунда игры #{game_round}")
                                                
                                                # Защита от бесконечного зацикливания
                                                if game_round > max_game_rounds:
                                                    logger.warning(f"Достигнуто максимальное количество раундов ({max_game_rounds}). Завершаем работу.")
                                                    return False
                                                
                                                # Отключаем звук в браузере перед первым раундом
                                                if game_round == 1:
                                                    try:
                                                        logger.info("Отключение звука в браузере...")
                                                        # Ищем кнопку звука по SVG с классом lucide-volume2 или lucide-volume-2
                                                        volume_button_selectors = [
                                                            'button[data-slot="button"] svg.lucide-volume2',
                                                            'button[data-slot="button"] svg.lucide-volume-2',
                                                            'button[data-slot="button"]:has(svg.lucide-volume2)',
                                                            'button[data-slot="button"]:has(svg.lucide-volume-2)',
                                                        ]
                                                        
                                                        sound_disabled = False
                                                        for volume_selector in volume_button_selectors:
                                                            try:
                                                                if 'svg' in volume_selector:
                                                                    # Если селектор для SVG, ищем родительскую кнопку
                                                                    svg_element = page.locator(volume_selector).first
                                                                    if await svg_element.is_visible(timeout=2000):
                                                                        # Находим родительскую кнопку через XPath или через locator
                                                                        volume_button = svg_element.locator('xpath=ancestor::button').first
                                                                        await volume_button.click()
                                                                        logger.success("Звук отключен")
                                                                        sound_disabled = True
                                                                        await asyncio.sleep(0.5)
                                                                        break
                                                                else:
                                                                    # Если селектор для кнопки напрямую
                                                                    volume_button = page.locator(volume_selector).first
                                                                    if await volume_button.is_visible(timeout=2000):
                                                                        await volume_button.click()
                                                                        logger.success("Звук отключен")
                                                                        sound_disabled = True
                                                                        await asyncio.sleep(0.5)
                                                                        break
                                                            except Exception:
                                                                continue
                                                        
                                                        # Альтернативный способ: ищем кнопку с data-slot="button" и SVG внутри
                                                        if not sound_disabled:
                                                            try:
                                                                all_buttons = await page.query_selector_all('button[data-slot="button"]')
                                                                for button in all_buttons:
                                                                    # Проверяем, есть ли внутри SVG с классом volume
                                                                    svg_content = await button.query_selector('svg.lucide-volume2, svg.lucide-volume-2')
                                                                    if svg_content:
                                                                        await button.click()
                                                                        logger.success("Звук отключен (через альтернативный метод)")
                                                                        sound_disabled = True
                                                                        await asyncio.sleep(0.5)
                                                                        break
                                                            except Exception as e:
                                                                logger.debug(f"Не удалось отключить звук альтернативным методом: {e}")
                                                        
                                                        if not sound_disabled:
                                                            logger.debug("Кнопка отключения звука не найдена")
                                                    except Exception as e:
                                                        logger.debug(f"Ошибка при отключении звука: {e}")
                                                
                                                # Проверяем наличие кнопки "Out of IP Games" перед началом раунда
                                                out_of_ip_games_selector = 'button[data-slot="button"][aria-label="Out of IP Games"]'
                                                out_of_ip_found = False
                                                
                                                try:
                                                    out_of_ip_button = page.locator(out_of_ip_games_selector).first
                                                    is_visible = await out_of_ip_button.is_visible(timeout=2000)
                                                    if is_visible:
                                                        out_of_ip_found = True
                                                except Exception:
                                                    pass
                                                
                                                # Альтернативная проверка по тексту
                                                if not out_of_ip_found:
                                                    try:
                                                        out_of_ip_text_selector = 'button:has-text("Out of IP Games")'
                                                        out_of_ip_text_button = page.locator(out_of_ip_text_selector).first
                                                        is_visible = await out_of_ip_text_button.is_visible(timeout=2000)
                                                        if is_visible:
                                                            out_of_ip_found = True
                                                    except Exception:
                                                        pass
                                                
                                                if out_of_ip_found:
                                                    logger.warning("Out of IP Games")
                                                    logger.info("Обнаружена кнопка 'Out of IP Games', завершаем работу")
                                                    return None  # Возвращаем None для случая "Out of IP Games"
                                                
                                                # Ищем и кликаем на кнопку "Play with IP"
                                                play_with_ip_selector = 'button[data-slot="button"][aria-label="Play with IP"]'
                                                play_with_ip_clicked = False
                                                
                                                try:
                                                    logger.info("Ожидание кнопки 'Play with IP' на основной странице...")
                                                    await page.wait_for_selector(play_with_ip_selector, timeout=30000)
                                                    await page.click(play_with_ip_selector)
                                                    logger.success("Кнопка 'Play with IP' нажата успешно")
                                                    play_with_ip_clicked = True
                                                    failed_attempts = 0  # Сбрасываем счетчик при успехе
                                                except Exception as e:
                                                    # Пробуем альтернативные селекторы
                                                    logger.debug(f"Не удалось найти кнопку по селектору {play_with_ip_selector}, пробуем альтернативные: {e}")
                                                    try:
                                                        # Пробуем по data-slot и тексту
                                                        text_selector = 'button[data-slot="button"]:has-text("Play with IP")'
                                                        await page.wait_for_selector(text_selector, timeout=10000)
                                                        await page.click(text_selector)
                                                        logger.success("Кнопка 'Play with IP' нажата успешно (через альтернативный селектор)")
                                                        play_with_ip_clicked = True
                                                        failed_attempts = 0  # Сбрасываем счетчик при успехе
                                                    except Exception as e2:
                                                        try:
                                                            # Пробуем просто по тексту
                                                            simple_text_selector = 'button:has-text("Play with IP")'
                                                            await page.wait_for_selector(simple_text_selector, timeout=10000)
                                                            await page.click(simple_text_selector)
                                                            logger.success("Кнопка 'Play with IP' нажата успешно (через текстовый селектор)")
                                                            play_with_ip_clicked = True
                                                            failed_attempts = 0  # Сбрасываем счетчик при успехе
                                                        except Exception as e3:
                                                            logger.error(f"Не удалось найти кнопку 'Play with IP': {e3}")
                                                            failed_attempts += 1
                                                            logger.warning(f"Неудачная попытка {failed_attempts}/{max_failed_attempts}")
                                                            
                                                            # Если слишком много неудачных попыток подряд, завершаем работу
                                                            if failed_attempts >= max_failed_attempts:
                                                                logger.error(f"Превышено максимальное количество неудачных попыток ({max_failed_attempts}). Завершаем работу.")
                                                                return False
                                                            
                                                            # Проверяем "Out of IP Games" и продолжаем цикл
                                                            await asyncio.sleep(2)
                                                            out_of_ip_games_selector = 'button[data-slot="button"][aria-label="Out of IP Games"]'
                                                            try:
                                                                out_of_ip_button = page.locator(out_of_ip_games_selector).first
                                                                if await out_of_ip_button.is_visible(timeout=2000):
                                                                    logger.warning("Out of IP Games")
                                                                    return None
                                                            except Exception:
                                                                pass
                                                            
                                                            # Обновляем страницу перед следующей попыткой
                                                            logger.info("Обновление страницы перед следующей попыткой...")
                                                            await page.reload(wait_until="networkidle", timeout=60000)
                                                            await asyncio.sleep(3)
                                                            continue
                                                
                                                # Если "Play with IP" была нажата, проверяем ставку и запускаем игру
                                                if play_with_ip_clicked:
                                                    await asyncio.sleep(2)  # Даём время на загрузку интерфейса игры
                                                    
                                                    # Проверяем наличие кнопки "Start again" после нажатия "Play with IP"
                                                    # (может появиться если транзакция не была обнаружена)
                                                    start_again_after_play = False
                                                    try:
                                                        logger.info("Проверка наличия кнопки 'Start again' после 'Play with IP'...")
                                                        # Пробуем разные селекторы для "Start again"
                                                        start_again_selectors = [
                                                            'button[data-slot="button"][aria-label="Start again"]',
                                                            'button[data-slot="button"]:has-text("Start again")',
                                                            'button:has-text("Start again")',
                                                        ]
                                                        
                                                        for selector in start_again_selectors:
                                                            try:
                                                                start_again_btn = page.locator(selector).first
                                                                is_visible = await start_again_btn.is_visible(timeout=3000)
                                                                if is_visible:
                                                                    logger.info("Найдена кнопка 'Start again' после 'Play with IP', кликаем на неё...")
                                                                    await start_again_btn.click()
                                                                    logger.success("Кнопка 'Start again' нажата успешно")
                                                                    start_again_after_play = True
                                                                    await asyncio.sleep(2)  # Даём время на открытие окна расширения
                                                                    break
                                                            except Exception:
                                                                continue
                                                    except Exception as e:
                                                        logger.debug(f"Ошибка при проверке 'Start again' после 'Play with IP': {e}")
                                                    
                                                    # Если "Start again" была нажата, переходим к обработке окна расширения
                                                    if start_again_after_play:
                                                        # Ждём появления нового окна расширения для подписи транзакции
                                                        logger.info("Ожидание нового окна расширения для подписи транзакции...")
                                                        transaction_sign_page = None
                                                        
                                                        # Ждём появления новой страницы расширения (может открыться с задержкой)
                                                        for attempt in range(15):  # Пробуем до 15 раз с интервалом 0.5 сек
                                                            for existing_page in context.pages:
                                                                # Ищем страницу расширения, которая отличается от предыдущих
                                                                if (existing_page.url.startswith(f"chrome-extension://{extension_id}/") 
                                                                    and existing_page != extension_page 
                                                                    and existing_page != sign_page):
                                                                    transaction_sign_page = existing_page
                                                                    break
                                                            if transaction_sign_page:
                                                                break
                                                            await asyncio.sleep(0.5)
                                                        
                                                        if not transaction_sign_page:
                                                            logger.warning("Новое окно расширения для транзакции не найдено, пробуем найти любую новую страницу расширения")
                                                            # Пробуем найти любую новую страницу расширения
                                                            for existing_page in context.pages:
                                                                if (existing_page.url.startswith("chrome-extension://") 
                                                                    and existing_page != extension_page 
                                                                    and existing_page != sign_page):
                                                                    transaction_sign_page = existing_page
                                                                    break
                                                        
                                                        if transaction_sign_page:
                                                            logger.info("Обработка окна подписи транзакции...")
                                                            
                                                            # Кликаем на кнопку "Sign"
                                                            sign_button_selector = 'button:has-text("Sign")'
                                                            
                                                            try:
                                                                logger.info("Ожидание кнопки 'Sign' в окне подписи транзакции...")
                                                                await transaction_sign_page.wait_for_selector(sign_button_selector, timeout=30000)
                                                                await transaction_sign_page.click(sign_button_selector)
                                                                logger.success("Кнопка 'Sign' нажата успешно")
                                                                await asyncio.sleep(1)  # Даём время на обработку
                                                            except Exception as e:
                                                                # Пробуем альтернативные селекторы
                                                                logger.debug(f"Не удалось найти кнопку по селектору {sign_button_selector}, пробуем альтернативные: {e}")
                                                                try:
                                                                    # Пробуем регистронезависимо
                                                                    sign_text_selector = 'button:has-text("Sign"), button:has-text("sign")'
                                                                    await transaction_sign_page.wait_for_selector(sign_text_selector, timeout=10000)
                                                                    await transaction_sign_page.click(sign_text_selector)
                                                                    logger.success("Кнопка 'Sign' нажата успешно (через альтернативный селектор)")
                                                                    await asyncio.sleep(1)
                                                                except Exception as e2:
                                                                    logger.warning(f"Не удалось найти кнопку 'Sign': {e2}, продолжаем...")
                                                            
                                                            # Кликаем на кнопку "Confirm"
                                                            confirm_button_selector = 'button:has-text("Confirm")'
                                                            confirm_clicked = False
                                                            
                                                            try:
                                                                logger.info("Ожидание кнопки 'Confirm' в окне подписи транзакции...")
                                                                await transaction_sign_page.wait_for_selector(confirm_button_selector, timeout=30000)
                                                                await transaction_sign_page.click(confirm_button_selector)
                                                                logger.success("Кнопка 'Confirm' нажата успешно")
                                                                confirm_clicked = True
                                                            except Exception as e:
                                                                # Пробуем альтернативные селекторы
                                                                logger.debug(f"Не удалось найти кнопку по селектору {confirm_button_selector}, пробуем альтернативные: {e}")
                                                                try:
                                                                    # Пробуем регистронезависимо
                                                                    confirm_text_selector = 'button:has-text("Confirm"), button:has-text("confirm")'
                                                                    await transaction_sign_page.wait_for_selector(confirm_text_selector, timeout=10000)
                                                                    await transaction_sign_page.click(confirm_text_selector)
                                                                    logger.success("Кнопка 'Confirm' нажата успешно (через альтернативный селектор)")
                                                                    confirm_clicked = True
                                                                except Exception as e2:
                                                                    logger.error(f"Не удалось найти кнопку 'Confirm': {e2}")
                                                                    # Продолжаем выполнение даже если не нашли Confirm
                                                            
                                                            # После подписания транзакции "Start again" игра начинается автоматически
                                                            # Переходим к ожиданию активных кнопок (tiles) для клика
                                                            if confirm_clicked or start_again_after_play:
                                                                await asyncio.sleep(2)  # Даём время на обработку транзакции и начало игры
                                                                
                                                                # Ждём, когда кнопки (tiles) станут активными для клика
                                                                logger.info("Ожидание активации кнопок (tiles) для клика после 'Start again'...")
                                                                
                                                                # Ищем контейнер с кнопками
                                                                tiles_container_selector = 'div.bg-background.relative.flex-1.rounded-lg'
                                                                active_tile_selector = 'button[aria-label^="Tile"][aria-label*="row 0"]:not([disabled])'
                                                                
                                                                try:
                                                                    # Ждём появления контейнера
                                                                    await page.wait_for_selector(tiles_container_selector, timeout=30000)
                                                                    
                                                                    # Ждём, когда хотя бы одна кнопка станет активной (не disabled)
                                                                    max_wait_attempts = 30  # Максимум 30 секунд ожидания
                                                                    tile_clicked = False
                                                                    
                                                                    for wait_attempt in range(max_wait_attempts):
                                                                        try:
                                                                            # Ищем все активные кнопки в row 0
                                                                            active_tiles = await page.query_selector_all(active_tile_selector)
                                                                            
                                                                            if active_tiles:
                                                                                # Выбираем случайную активную кнопку
                                                                                random_tile = random.choice(active_tiles)
                                                                                tile_aria_label = await random_tile.get_attribute('aria-label')
                                                                                
                                                                                # Проверяем, что кнопка действительно не disabled
                                                                                is_disabled = await random_tile.get_attribute('disabled')
                                                                                if not is_disabled:
                                                                                    logger.info(f"Клик по случайной кнопке: {tile_aria_label}")
                                                                                    await random_tile.click()
                                                                                    logger.success(f"Кнопка '{tile_aria_label}' нажата успешно")
                                                                                    tile_clicked = True
                                                                                    break
                                                                                else:
                                                                                    logger.debug(f"Кнопка {tile_aria_label} всё ещё disabled, ждём...")
                                                                            else:
                                                                                logger.debug(f"Активные кнопки не найдены, попытка {wait_attempt + 1}/{max_wait_attempts}")
                                                                        except Exception as e:
                                                                            logger.debug(f"Ошибка при поиске активных кнопок: {e}")
                                                                        
                                                                        await asyncio.sleep(1)  # Ждём 1 секунду перед следующей попыткой
                                                                    
                                                                    if not tile_clicked:
                                                                        logger.warning("Не удалось найти активные кнопки для клика, пробуем альтернативный метод...")
                                                                        # Альтернативный метод: ищем любые кнопки без disabled
                                                                        try:
                                                                            all_tiles = await page.query_selector_all('button[aria-label^="Tile"][aria-label*="row 0"]')
                                                                            for tile in all_tiles:
                                                                                is_disabled = await tile.get_attribute('disabled')
                                                                                if not is_disabled:
                                                                                    tile_aria_label = await tile.get_attribute('aria-label')
                                                                                    logger.info(f"Клик по найденной активной кнопке: {tile_aria_label}")
                                                                                    await tile.click()
                                                                                    logger.success(f"Кнопка '{tile_aria_label}' нажата успешно")
                                                                                    tile_clicked = True
                                                                                    break
                                                                        except Exception as e:
                                                                            logger.warning(f"Не удалось кликнуть по кнопке альтернативным методом: {e}")
                                                                    
                                                                    if tile_clicked:
                                                                        await asyncio.sleep(1)  # Даём время на обработку клика
                                                                        
                                                                        # Проверяем наличие текста "DEATH TILE!" - если есть, игра проиграна
                                                                        await asyncio.sleep(2)  # Задержка перед проверкой "DEATH TILE!"
                                                                        
                                                                        # Проверяем наличие текста "DEATH TILE!" - если есть, игра проиграна
                                                                        death_tile_found = False
                                                                        try:
                                                                            logger.info("Проверка наличия текста 'DEATH TILE!'...")
                                                                            
                                                                            # Пробуем разные способы поиска текста "DEATH TILE!"
                                                                            # Вариант 1: через text locator
                                                                            try:
                                                                                death_tile_text = page.locator('text=/DEATH TILE!/i').first
                                                                                is_visible = await death_tile_text.is_visible(timeout=2000)
                                                                                if is_visible:
                                                                                    logger.warning("Обнаружен текст 'DEATH TILE!' - игра проиграна, Cash out не требуется")
                                                                                    death_tile_found = True
                                                                            except Exception:
                                                                                # Вариант 2: через поиск по тексту в DOM
                                                                                try:
                                                                                    page_text = await page.text_content()
                                                                                    if page_text and "DEATH TILE!" in page_text.upper():
                                                                                        logger.warning("Обнаружен текст 'DEATH TILE!' (через text_content) - игра проиграна, Cash out не требуется")
                                                                                        death_tile_found = True
                                                                                except Exception:
                                                                                    # Вариант 3: через evaluate
                                                                                    try:
                                                                                        death_tile_exists = await page.evaluate("""
                                                                                            () => {
                                                                                                const text = document.body.innerText || document.body.textContent || '';
                                                                                                return text.toUpperCase().includes('DEATH TILE!');
                                                                                            }
                                                                                        """)
                                                                                        if death_tile_exists:
                                                                                            logger.warning("Обнаружен текст 'DEATH TILE!' (через evaluate) - игра проиграна, Cash out не требуется")
                                                                                            death_tile_found = True
                                                                                    except Exception as e:
                                                                                        logger.debug(f"Не удалось проверить наличие 'DEATH TILE!' через evaluate: {e}")
                                                                        except Exception as e:
                                                                            # Текст не найден - это нормально, продолжаем
                                                                            logger.debug(f"Текст 'DEATH TILE!' не найден: {e}, продолжаем проверку Cash out")
                                                                        
                                                                        # Если "DEATH TILE!" найден, пропускаем Cash out и переходим к следующему раунду
                                                                        if death_tile_found:
                                                                            logger.info("Игра проиграна, пропускаем Cash out и переходим к следующему раунду")
                                                                            # Продолжаем цикл для следующего раунда
                                                                            await asyncio.sleep(2)  # Даём время на обработку
                                                                            # Возвращаемся на основную страницу для следующего раунда
                                                                            logger.info("Возврат на основную страницу для следующего раунда...")
                                                                            await page.goto("https://soneium.superstake.fun/", wait_until="networkidle", timeout=60000)
                                                                            await asyncio.sleep(2)  # Даём время на загрузку страницы
                                                                            
                                                                            # Проверяем наличие кнопки "Out of IP Games" после проигрыша
                                                                            out_of_ip_games_selector = 'button[data-slot="button"][aria-label="Out of IP Games"]'
                                                                            out_of_ip_found = False
                                                                            
                                                                            try:
                                                                                out_of_ip_button = page.locator(out_of_ip_games_selector).first
                                                                                is_visible = await out_of_ip_button.is_visible(timeout=2000)
                                                                                if is_visible:
                                                                                    out_of_ip_found = True
                                                                            except Exception:
                                                                                pass
                                                                            
                                                                            # Альтернативная проверка по тексту
                                                                            if not out_of_ip_found:
                                                                                try:
                                                                                    out_of_ip_text_selector = 'button:has-text("Out of IP Games")'
                                                                                    out_of_ip_text_button = page.locator(out_of_ip_text_selector).first
                                                                                    is_visible = await out_of_ip_text_button.is_visible(timeout=2000)
                                                                                    if is_visible:
                                                                                        out_of_ip_found = True
                                                                                except Exception:
                                                                                    pass
                                                                            
                                                                            if out_of_ip_found:
                                                                                logger.warning("Out of IP Games")
                                                                                logger.info("Обнаружена кнопка 'Out of IP Games' после проигрыша, завершаем работу")
                                                                                return None  # Возвращаем None для случая "Out of IP Games"
                                                                            
                                                                            # Продолжаем цикл для следующего раунда
                                                                            logger.info(f"Раунд #{game_round} завершён (проигрыш), переходим к следующему раунду...")
                                                                            failed_attempts = 0  # Сбрасываем счетчик неудачных попыток
                                                                            
                                                                            # Рандомная задержка между играми от 10 до 30 секунд
                                                                            delay = random.randint(10, 30)
                                                                            logger.info(f"Ожидание {delay} секунд перед следующим раундом...")
                                                                            await asyncio.sleep(delay)
                                                                            
                                                                            continue  # Переходим к следующей итерации цикла игры
                                                                        
                                                                        # Проверяем наличие кнопки "Cash out"
                                                                        logger.info("Проверка наличия кнопки 'Cash out'...")
                                                                        cash_out_button_selector = 'button[data-slot="button"][aria-label="Cash out current winnings"]'
                                                                        cash_out_clicked = False
                                                                        
                                                                        try:
                                                                            # Ждём появления кнопки с таймаутом 10 секунд
                                                                            await page.wait_for_selector(cash_out_button_selector, timeout=10000)
                                                                            
                                                                            # Проверяем, что кнопка не disabled
                                                                            cash_out_button = page.locator(cash_out_button_selector).first
                                                                            is_disabled = await cash_out_button.get_attribute('disabled')
                                                                            
                                                                            if not is_disabled:
                                                                                logger.info("Кнопка 'Cash out' найдена и активна, кликаем...")
                                                                                await cash_out_button.click()
                                                                                logger.success("Кнопка 'Cash out' нажата успешно")
                                                                                cash_out_clicked = True
                                                                                await asyncio.sleep(2)  # Даём время на открытие окна расширения
                                                                            else:
                                                                                logger.info("Кнопка 'Cash out' найдена, но не активна (disabled)")
                                                                        except Exception as e:
                                                                            logger.info(f"Кнопка 'Cash out' не появилась или не найдена: {e}")
                                                                        
                                                                        # Если кнопка "Cash out" была нажата, обрабатываем окно расширения
                                                                        if cash_out_clicked:
                                                                            # Ждём появления нового окна расширения для подтверждения транзакции
                                                                            logger.info("Ожидание нового окна расширения для подтверждения транзакции...")
                                                                            cashout_sign_page = None
                                                                            
                                                                            # Ждём появления новой страницы расширения (может открыться с задержкой)
                                                                            for attempt in range(15):  # Пробуем до 15 раз с интервалом 0.5 сек
                                                                                for existing_page in context.pages:
                                                                                    # Ищем страницу расширения, которая отличается от предыдущих
                                                                                    if (existing_page.url.startswith(f"chrome-extension://{extension_id}/") 
                                                                                        and existing_page != extension_page 
                                                                                        and existing_page != sign_page
                                                                                        and existing_page != transaction_sign_page):
                                                                                        cashout_sign_page = existing_page
                                                                                        break
                                                                                if cashout_sign_page:
                                                                                    break
                                                                                await asyncio.sleep(0.5)
                                                                            
                                                                            if not cashout_sign_page:
                                                                                logger.warning("Новое окно расширения для cashout не найдено, пробуем найти любую новую страницу расширения")
                                                                                # Пробуем найти любую новую страницу расширения
                                                                                for existing_page in context.pages:
                                                                                    if (existing_page.url.startswith("chrome-extension://") 
                                                                                        and existing_page != extension_page 
                                                                                        and existing_page != sign_page
                                                                                        and existing_page != transaction_sign_page):
                                                                                        cashout_sign_page = existing_page
                                                                                        break
                                                                            
                                                                            if cashout_sign_page:
                                                                                logger.info("Обработка окна подтверждения транзакции cashout...")
                                                                                
                                                                                # Кликаем на кнопку "Sign"
                                                                                sign_button_selector = 'button:has-text("Sign")'
                                                                                
                                                                                try:
                                                                                    logger.info("Ожидание кнопки 'Sign' в окне подтверждения cashout...")
                                                                                    await cashout_sign_page.wait_for_selector(sign_button_selector, timeout=30000)
                                                                                    await cashout_sign_page.click(sign_button_selector)
                                                                                    logger.success("Кнопка 'Sign' нажата успешно")
                                                                                    await asyncio.sleep(1)  # Даём время на обработку
                                                                                except Exception as e:
                                                                                    # Пробуем альтернативные селекторы
                                                                                    logger.debug(f"Не удалось найти кнопку по селектору {sign_button_selector}, пробуем альтернативные: {e}")
                                                                                    try:
                                                                                        # Пробуем регистронезависимо
                                                                                        sign_text_selector = 'button:has-text("Sign"), button:has-text("sign")'
                                                                                        await cashout_sign_page.wait_for_selector(sign_text_selector, timeout=10000)
                                                                                        await cashout_sign_page.click(sign_text_selector)
                                                                                        logger.success("Кнопка 'Sign' нажата успешно (через альтернативный селектор)")
                                                                                        await asyncio.sleep(1)
                                                                                    except Exception as e2:
                                                                                        logger.warning(f"Не удалось найти кнопку 'Sign': {e2}, продолжаем...")
                                                                                
                                                                                # Кликаем на кнопку "Confirm"
                                                                                confirm_button_selector = 'button:has-text("Confirm")'
                                                                                
                                                                                try:
                                                                                    logger.info("Ожидание кнопки 'Confirm' в окне подтверждения cashout...")
                                                                                    await cashout_sign_page.wait_for_selector(confirm_button_selector, timeout=30000)
                                                                                    await cashout_sign_page.click(confirm_button_selector)
                                                                                    logger.success("Кнопка 'Confirm' нажата успешно")
                                                                                    await asyncio.sleep(1)  # Даём время на обработку
                                                                                except Exception as e:
                                                                                    # Пробуем альтернативные селекторы
                                                                                    logger.debug(f"Не удалось найти кнопку по селектору {confirm_button_selector}, пробуем альтернативные: {e}")
                                                                                    try:
                                                                                        # Пробуем регистронезависимо
                                                                                        confirm_text_selector = 'button:has-text("Confirm"), button:has-text("confirm")'
                                                                                        await cashout_sign_page.wait_for_selector(confirm_text_selector, timeout=10000)
                                                                                        await cashout_sign_page.click(confirm_text_selector)
                                                                                        logger.success("Кнопка 'Confirm' нажата успешно (через альтернативный селектор)")
                                                                                        await asyncio.sleep(1)
                                                                                    except Exception as e2:
                                                                                        logger.warning(f"Не удалось найти кнопку 'Confirm': {e2}")
                                                                        
                                                                        # После завершения раунда проверяем "Out of IP Games" и продолжаем цикл
                                                                        await asyncio.sleep(2)  # Даём время на завершение раунда
                                                                        
                                                                        # Возвращаемся на основную страницу для следующего раунда
                                                                        logger.info("Возврат на основную страницу для следующего раунда...")
                                                                        await page.goto("https://soneium.superstake.fun/", wait_until="networkidle", timeout=60000)
                                                                        await asyncio.sleep(2)  # Даём время на загрузку страницы
                                                                        
                                                                        # Проверяем наличие кнопки "Out of IP Games" после раунда
                                                                        out_of_ip_games_selector = 'button[data-slot="button"][aria-label="Out of IP Games"]'
                                                                        out_of_ip_found = False
                                                                        
                                                                        try:
                                                                            out_of_ip_button = page.locator(out_of_ip_games_selector).first
                                                                            is_visible = await out_of_ip_button.is_visible(timeout=2000)
                                                                            if is_visible:
                                                                                out_of_ip_found = True
                                                                        except Exception:
                                                                            pass
                                                                        
                                                                        # Альтернативная проверка по тексту
                                                                        if not out_of_ip_found:
                                                                            try:
                                                                                out_of_ip_text_selector = 'button:has-text("Out of IP Games")'
                                                                                out_of_ip_text_button = page.locator(out_of_ip_text_selector).first
                                                                                is_visible = await out_of_ip_text_button.is_visible(timeout=2000)
                                                                                if is_visible:
                                                                                    out_of_ip_found = True
                                                                            except Exception:
                                                                                pass
                                                                        
                                                                        if out_of_ip_found:
                                                                            logger.warning("Out of IP Games")
                                                                            logger.info("Обнаружена кнопка 'Out of IP Games' после раунда, завершаем работу")
                                                                            return None  # Возвращаем None для случая "Out of IP Games"
                                                                        
                                                                        # Продолжаем цикл для следующего раунда
                                                                        logger.info(f"Раунд #{game_round} завершён, переходим к следующему раунду...")
                                                                        failed_attempts = 0  # Сбрасываем счетчик неудачных попыток при успешном раунде
                                                                        
                                                                        # Рандомная задержка между играми от 10 до 30 секунд
                                                                        delay = random.randint(10, 30)
                                                                        logger.info(f"Ожидание {delay} секунд перед следующим раундом...")
                                                                        await asyncio.sleep(delay)
                                                                        
                                                                        continue  # Переходим к следующей итерации цикла игры
                                                                except Exception as e:
                                                                    logger.warning(f"Ошибка при ожидании активных кнопок после 'Start again': {e}, продолжаем...")
                                                    
                                                    # Если "Start again" не была нажата, продолжаем с обычной логикой
                                                    if not start_again_after_play:
                                                        # Продолжаем с проверкой ставки и "Start Game"
                                                        
                                                        # Проверяем, что установлена ставка 10 IP
                                                        bet_10_ip_selector = 'button[aria-label="Select 10 IP"][aria-pressed="true"]'
                                                        
                                                        try:
                                                            logger.info("Проверка ставки 10 IP...")
                                                            await page.wait_for_selector(bet_10_ip_selector, timeout=30000)
                                                            # Проверяем, что кнопка действительно выбрана (aria-pressed="true")
                                                            is_selected = await page.get_attribute(bet_10_ip_selector, "aria-pressed")
                                                            if is_selected == "true":
                                                                logger.success("Ставка 10 IP установлена")
                                                            else:
                                                                logger.warning("Ставка 10 IP не установлена, пытаемся кликнуть...")
                                                                await page.click(bet_10_ip_selector)
                                                                await asyncio.sleep(1)
                                                        except Exception as e:
                                                            logger.warning(f"Не удалось проверить/установить ставку 10 IP: {e}, продолжаем...")
                                                            # Пробуем альтернативный селектор
                                                            try:
                                                                alt_selector = 'button[aria-label="Select 10 IP"]'
                                                                await page.wait_for_selector(alt_selector, timeout=10000)
                                                                is_selected = await page.get_attribute(alt_selector, "aria-pressed")
                                                                if is_selected != "true":
                                                                    await page.click(alt_selector)
                                                                    await asyncio.sleep(1)
                                                                logger.info("Ставка 10 IP проверена/установлена (через альтернативный селектор)")
                                                            except Exception as e2:
                                                                logger.warning(f"Не удалось установить ставку 10 IP: {e2}, продолжаем...")
                                                        
                                                        # Проверяем нижний коэффициент (Row 0 multiplier) - должен быть 1.14х
                                                        logger.info("Проверка нижнего коэффициента (Row 0 multiplier)...")
                                                        target_multiplier = "1.14"
                                                        max_shuffle_attempts = 20  # Максимальное количество попыток переключения
                                                        multiplier_correct = False
                                                        
                                                        for shuffle_attempt in range(max_shuffle_attempts):
                                                            try:
                                                                # Ищем элемент с коэффициентом Row 0 - пробуем разные варианты селекторов
                                                                multiplier_text = None
                                                                current_multiplier = None
                                                                
                                                                # Вариант 1: по aria-label с "Row 0 multiplier"
                                                                try:
                                                                    row_0_multiplier_selector = '[aria-label*="Row 0 multiplier"]'
                                                                    await page.wait_for_selector(row_0_multiplier_selector, timeout=3000)
                                                                    multiplier_element = page.locator(row_0_multiplier_selector).first
                                                                    # Получаем aria-label атрибут
                                                                    aria_label = await multiplier_element.get_attribute('aria-label')
                                                                    if aria_label:
                                                                        multiplier_text = aria_label
                                                                    else:
                                                                        # Если aria-label не найден, получаем текст
                                                                        multiplier_text = await multiplier_element.text_content()
                                                                except Exception:
                                                                    pass
                                                                
                                                                # Вариант 2: ищем элемент с data-row-index="0" и извлекаем коэффициент из дочернего элемента
                                                                if not multiplier_text:
                                                                    try:
                                                                        row_0_container = page.locator('[data-row-index="0"]').first
                                                                        await row_0_container.wait_for(timeout=3000)
                                                                        # Ищем внутри контейнера элемент с aria-label или текстом коэффициента
                                                                        multiplier_element = row_0_container.locator('[aria-label*="multiplier"], div:has-text(/\\d+\\.\\d+x?/)').first
                                                                        aria_label = await multiplier_element.get_attribute('aria-label')
                                                                        if aria_label and "Row 0 multiplier" in aria_label:
                                                                            multiplier_text = aria_label
                                                                        else:
                                                                            multiplier_text = await multiplier_element.text_content()
                                                                    except Exception:
                                                                        pass
                                                                
                                                                # Вариант 3: используем evaluate для поиска в DOM по data-row-index="0"
                                                                if not multiplier_text:
                                                                    try:
                                                                        multiplier_text = await page.evaluate("""
                                                                            () => {
                                                                                // Ищем контейнер с data-row-index="0"
                                                                                const row0Container = document.querySelector('[data-row-index="0"]');
                                                                                if (row0Container) {
                                                                                    // Ищем элемент с aria-label содержащим "Row 0 multiplier"
                                                                                    const multiplierEl = row0Container.querySelector('[aria-label*="Row 0 multiplier"]');
                                                                                    if (multiplierEl) {
                                                                                        return multiplierEl.getAttribute('aria-label') || multiplierEl.textContent;
                                                                                    }
                                                                                    // Или ищем div с текстом коэффициента (например, "1.14x")
                                                                                    const textEl = Array.from(row0Container.querySelectorAll('div')).find(el => {
                                                                                        const text = el.textContent || '';
                                                                                        return /\\d+\\.\\d+x?/.test(text);
                                                                                    });
                                                                                    if (textEl) {
                                                                                        return textEl.textContent;
                                                                                    }
                                                                                }
                                                                                return null;
                                                                            }
                                                                        """)
                                                                    except Exception:
                                                                        pass
                                                                
                                                                # Вариант 4: ищем все элементы с aria-label содержащим "Row 0 multiplier"
                                                                if not multiplier_text:
                                                                    try:
                                                                        all_elements = await page.query_selector_all('[aria-label*="Row 0 multiplier"]')
                                                                        if all_elements:
                                                                            elem = all_elements[0]
                                                                            multiplier_text = await elem.get_attribute('aria-label')
                                                                            if not multiplier_text:
                                                                                multiplier_text = await elem.text_content()
                                                                    except Exception:
                                                                        pass
                                                                
                                                                if multiplier_text:
                                                                    logger.debug(f"Найден текст коэффициента: {multiplier_text}")
                                                                    # Извлекаем значение коэффициента из текста (например, "Row 0 multiplier: 1.14" или "1.14x")
                                                                    # Ищем паттерн: число с точкой, возможно с "x" в конце
                                                                    multiplier_match = re.search(r'(\d+\.\d+)', multiplier_text)
                                                                    if multiplier_match:
                                                                        current_multiplier = multiplier_match.group(1)
                                                                        logger.info(f"Текущий нижний коэффициент: {current_multiplier}x")
                                                                        
                                                                        if current_multiplier == target_multiplier:
                                                                            logger.success(f"Нижний коэффициент установлен на {target_multiplier}x")
                                                                            multiplier_correct = True
                                                                            break
                                                                        else:
                                                                            logger.info(f"Нижний коэффициент {current_multiplier}x не равен {target_multiplier}x, используем Shuffle...")
                                                                    else:
                                                                        logger.warning(f"Не удалось извлечь значение коэффициента из текста: {multiplier_text}")
                                                                else:
                                                                    logger.warning("Не удалось найти элемент с коэффициентом Row 0")
                                                            except Exception as e:
                                                                logger.debug(f"Ошибка при проверке коэффициента: {e}")
                                                            
                                                            # Если коэффициент не правильный, кликаем на Shuffle
                                                            if not multiplier_correct:
                                                                try:
                                                                    shuffle_button_selector = 'button:has-text("Shuffle"), button[name="Shuffle"]'
                                                                    await page.wait_for_selector(shuffle_button_selector, timeout=5000)
                                                                    await page.click(shuffle_button_selector)
                                                                    logger.info(f"Кнопка 'Shuffle' нажата (попытка {shuffle_attempt + 1}/{max_shuffle_attempts})")
                                                                    await asyncio.sleep(1)  # Даём время на обновление коэффициентов
                                                                except Exception as e:
                                                                    logger.warning(f"Не удалось найти/нажать кнопку Shuffle: {e}")
                                                                    # Пробуем альтернативный селектор
                                                                    try:
                                                                        alt_shuffle_selector = 'button[name*="Shuffle"]'
                                                                        await page.wait_for_selector(alt_shuffle_selector, timeout=3000)
                                                                        await page.click(alt_shuffle_selector)
                                                                        logger.info(f"Кнопка 'Shuffle' нажата через альтернативный селектор (попытка {shuffle_attempt + 1}/{max_shuffle_attempts})")
                                                                        await asyncio.sleep(1)
                                                                    except Exception as e2:
                                                                        logger.error(f"Не удалось найти кнопку Shuffle: {e2}")
                                                                        break
                                                        
                                                        if not multiplier_correct:
                                                            logger.warning(f"Не удалось установить нижний коэффициент на {target_multiplier}x после {max_shuffle_attempts} попыток, продолжаем...")
                                                        
                                                        # Проверяем наличие кнопки "Out of IP Games" перед нажатием "Start Game"
                                                        logger.info("Проверка наличия кнопки 'Out of IP Games' перед 'Start Game'...")
                                                        out_of_ip_games_selector = 'button[data-slot="button"][aria-label="Out of IP Games"]'
                                                        out_of_ip_found = False
                                                        
                                                        try:
                                                            # Проверяем, есть ли кнопка на странице (без ожидания)
                                                            out_of_ip_button = page.locator(out_of_ip_games_selector).first
                                                            is_visible = await out_of_ip_button.is_visible(timeout=2000)
                                                            if is_visible:
                                                                out_of_ip_found = True
                                                        except Exception:
                                                            # Кнопка не найдена - это нормально, продолжаем
                                                            pass
                                                        
                                                        # Альтернативная проверка по тексту
                                                        if not out_of_ip_found:
                                                            try:
                                                                out_of_ip_text_selector = 'button:has-text("Out of IP Games")'
                                                                out_of_ip_text_button = page.locator(out_of_ip_text_selector).first
                                                                is_visible = await out_of_ip_text_button.is_visible(timeout=2000)
                                                                if is_visible:
                                                                    out_of_ip_found = True
                                                            except Exception:
                                                                # Кнопка не найдена - это нормально, продолжаем
                                                                pass
                                                        
                                                        if out_of_ip_found:
                                                            logger.warning("Out of IP Games")
                                                            logger.info("Обнаружена кнопка 'Out of IP Games' перед 'Start Game', завершаем работу")
                                                            return None  # Возвращаем None для случая "Out of IP Games"
                                                        
                                                        # Проверяем наличие кнопки "Start again" перед "Start Game"
                                                        # (увеличиваем таймаут, так как кнопка может появиться с задержкой)
                                                        start_again_clicked = False
                                                        
                                                        try:
                                                            logger.info("Проверка наличия кнопки 'Start again' перед 'Start Game'...")
                                                            # Пробуем разные селекторы с увеличенным таймаутом (5 секунд)
                                                            start_again_selectors = [
                                                                'button[data-slot="button"][aria-label="Start again"]',
                                                                'button[data-slot="button"]:has-text("Start again")',
                                                                'button:has-text("Start again")',
                                                            ]
                                                            
                                                            for selector in start_again_selectors:
                                                                try:
                                                                    start_again_button = page.locator(selector).first
                                                                    is_visible = await start_again_button.is_visible(timeout=5000)
                                                                    if is_visible:
                                                                        logger.info(f"Найдена кнопка 'Start again' (селектор: {selector}), кликаем на неё...")
                                                                        await start_again_button.click()
                                                                        logger.success("Кнопка 'Start again' нажата успешно")
                                                                        start_again_clicked = True
                                                                        await asyncio.sleep(2)  # Даём время на открытие окна расширения
                                                                        break
                                                                except Exception:
                                                                    continue
                                                            
                                                            if not start_again_clicked:
                                                                logger.debug("Кнопка 'Start again' не найдена, используем 'Start Game'")
                                                        except Exception as e:
                                                            logger.debug(f"Ошибка при проверке 'Start again': {e}, используем 'Start Game'")
                                                        
                                                        # Если "Start again" не была нажата, кликаем на "Start Game"
                                                        if not start_again_clicked:
                                                            start_game_selector = 'button[data-slot="button"][aria-label="Start Game"]'
                                                            
                                                            try:
                                                                logger.info("Ожидание кнопки 'Start Game'...")
                                                                await page.wait_for_selector(start_game_selector, timeout=30000)
                                                                await page.click(start_game_selector)
                                                                logger.success("Кнопка 'Start Game' нажата успешно")
                                                                await asyncio.sleep(2)  # Даём время на открытие окна расширения
                                                            except Exception as e:
                                                                # Пробуем альтернативные селекторы
                                                                logger.debug(f"Не удалось найти кнопку по селектору {start_game_selector}, пробуем альтернативные: {e}")
                                                                try:
                                                                    # Пробуем по data-slot и тексту
                                                                    text_selector = 'button[data-slot="button"]:has-text("Start Game")'
                                                                    await page.wait_for_selector(text_selector, timeout=10000)
                                                                    await page.click(text_selector)
                                                                    logger.success("Кнопка 'Start Game' нажата успешно (через альтернативный селектор)")
                                                                    await asyncio.sleep(2)
                                                                except Exception as e2:
                                                                    try:
                                                                        # Пробуем просто по тексту
                                                                        simple_text_selector = 'button:has-text("Start Game")'
                                                                        await page.wait_for_selector(simple_text_selector, timeout=10000)
                                                                        await page.click(simple_text_selector)
                                                                        logger.success("Кнопка 'Start Game' нажата успешно (через текстовый селектор)")
                                                                        await asyncio.sleep(2)
                                                                    except Exception as e3:
                                                                        logger.error(f"Не удалось найти кнопку 'Start Game': {e3}")
                                                                        return False
                                                
                                                # Ждём появления нового окна расширения для подписи транзакции
                                                logger.info("Ожидание нового окна расширения для подписи транзакции...")
                                                transaction_sign_page = None
                                                
                                                # Ждём появления новой страницы расширения (может открыться с задержкой)
                                                for attempt in range(15):  # Пробуем до 15 раз с интервалом 0.5 сек
                                                    for existing_page in context.pages:
                                                        # Ищем страницу расширения, которая отличается от предыдущих
                                                        if (existing_page.url.startswith(f"chrome-extension://{extension_id}/") 
                                                            and existing_page != extension_page 
                                                            and existing_page != sign_page):
                                                            transaction_sign_page = existing_page
                                                            break
                                                    if transaction_sign_page:
                                                        break
                                                    await asyncio.sleep(0.5)
                                                
                                                if not transaction_sign_page:
                                                    logger.warning("Новое окно расширения для транзакции не найдено, пробуем найти любую новую страницу расширения")
                                                    # Пробуем найти любую новую страницу расширения
                                                    for existing_page in context.pages:
                                                        if (existing_page.url.startswith("chrome-extension://") 
                                                            and existing_page != extension_page 
                                                            and existing_page != sign_page):
                                                            transaction_sign_page = existing_page
                                                            break
                                                
                                                if transaction_sign_page:
                                                    logger.info("Обработка окна подписи транзакции...")
                                                    
                                                    # Кликаем на кнопку "Sign"
                                                    sign_button_selector = 'button:has-text("Sign")'
                                                    
                                                    try:
                                                        logger.info("Ожидание кнопки 'Sign' в окне подписи транзакции...")
                                                        await transaction_sign_page.wait_for_selector(sign_button_selector, timeout=30000)
                                                        await transaction_sign_page.click(sign_button_selector)
                                                        logger.success("Кнопка 'Sign' нажата успешно")
                                                        await asyncio.sleep(1)  # Даём время на обработку
                                                    except Exception as e:
                                                        # Пробуем альтернативные селекторы
                                                        logger.debug(f"Не удалось найти кнопку по селектору {sign_button_selector}, пробуем альтернативные: {e}")
                                                        try:
                                                            # Пробуем регистронезависимо
                                                            sign_text_selector = 'button:has-text("Sign"), button:has-text("sign")'
                                                            await transaction_sign_page.wait_for_selector(sign_text_selector, timeout=10000)
                                                            await transaction_sign_page.click(sign_text_selector)
                                                            logger.success("Кнопка 'Sign' нажата успешно (через альтернативный селектор)")
                                                            await asyncio.sleep(1)
                                                        except Exception as e2:
                                                            logger.warning(f"Не удалось найти кнопку 'Sign': {e2}, продолжаем...")
                                                    
                                                    # Кликаем на кнопку "Confirm"
                                                    confirm_button_selector = 'button:has-text("Confirm")'
                                                    confirm_clicked = False
                                                    
                                                    try:
                                                        logger.info("Ожидание кнопки 'Confirm' в окне подписи транзакции...")
                                                        await transaction_sign_page.wait_for_selector(confirm_button_selector, timeout=30000)
                                                        await transaction_sign_page.click(confirm_button_selector)
                                                        logger.success("Кнопка 'Confirm' нажата успешно")
                                                        confirm_clicked = True
                                                    except Exception as e:
                                                        # Пробуем альтернативные селекторы
                                                        logger.debug(f"Не удалось найти кнопку по селектору {confirm_button_selector}, пробуем альтернативные: {e}")
                                                        try:
                                                            # Пробуем регистронезависимо
                                                            confirm_text_selector = 'button:has-text("Confirm"), button:has-text("confirm")'
                                                            await transaction_sign_page.wait_for_selector(confirm_text_selector, timeout=10000)
                                                            await transaction_sign_page.click(confirm_text_selector)
                                                            logger.success("Кнопка 'Confirm' нажата успешно (через альтернативный селектор)")
                                                            confirm_clicked = True
                                                        except Exception as e2:
                                                            logger.error(f"Не удалось найти кнопку 'Confirm': {e2}")
                                                            return False
                                                    
                                                    # Если транзакция подписана, ждём активных кнопок и кликаем по случайной
                                                    if confirm_clicked:
                                                        await asyncio.sleep(2)  # Даём время на обработку транзакции и начало игры
                                                        
                                                        # Ждём, когда кнопки (tiles) станут активными для клика
                                                        logger.info("Ожидание активации кнопок (tiles) для клика...")
                                                        
                                                        # Ищем контейнер с кнопками
                                                        tiles_container_selector = 'div.bg-background.relative.flex-1.rounded-lg'
                                                        active_tile_selector = 'button[aria-label^="Tile"][aria-label*="row 0"]:not([disabled])'
                                                        
                                                        try:
                                                            # Ждём появления контейнера
                                                            await page.wait_for_selector(tiles_container_selector, timeout=30000)
                                                            
                                                            # Ждём, когда хотя бы одна кнопка станет активной (не disabled)
                                                            max_wait_attempts = 30  # Максимум 30 секунд ожидания
                                                            tile_clicked = False
                                                            
                                                            for wait_attempt in range(max_wait_attempts):
                                                                try:
                                                                    # Ищем все активные кнопки в row 0
                                                                    active_tiles = await page.query_selector_all(active_tile_selector)
                                                                    
                                                                    if active_tiles:
                                                                        # Выбираем случайную активную кнопку
                                                                        random_tile = random.choice(active_tiles)
                                                                        tile_aria_label = await random_tile.get_attribute('aria-label')
                                                                        
                                                                        # Проверяем, что кнопка действительно не disabled
                                                                        is_disabled = await random_tile.get_attribute('disabled')
                                                                        if not is_disabled:
                                                                            logger.info(f"Клик по случайной кнопке: {tile_aria_label}")
                                                                            await random_tile.click()
                                                                            logger.success(f"Кнопка '{tile_aria_label}' нажата успешно")
                                                                            tile_clicked = True
                                                                            break
                                                                        else:
                                                                            logger.debug(f"Кнопка {tile_aria_label} всё ещё disabled, ждём...")
                                                                    else:
                                                                        logger.debug(f"Активные кнопки не найдены, попытка {wait_attempt + 1}/{max_wait_attempts}")
                                                                except Exception as e:
                                                                    logger.debug(f"Ошибка при поиске активных кнопок: {e}")
                                                                
                                                                await asyncio.sleep(1)  # Ждём 1 секунду перед следующей попыткой
                                                            
                                                            if not tile_clicked:
                                                                logger.warning("Не удалось найти активные кнопки для клика, пробуем альтернативный метод...")
                                                                # Альтернативный метод: ищем любые кнопки без disabled
                                                                try:
                                                                    all_tiles = await page.query_selector_all('button[aria-label^="Tile"][aria-label*="row 0"]')
                                                                    for tile in all_tiles:
                                                                        is_disabled = await tile.get_attribute('disabled')
                                                                        if not is_disabled:
                                                                            tile_aria_label = await tile.get_attribute('aria-label')
                                                                            logger.info(f"Клик по найденной активной кнопке: {tile_aria_label}")
                                                                            await tile.click()
                                                                            logger.success(f"Кнопка '{tile_aria_label}' нажата успешно")
                                                                            tile_clicked = True
                                                                            break
                                                                except Exception as e:
                                                                    logger.warning(f"Не удалось кликнуть по кнопке альтернативным методом: {e}")
                                                            
                                                            if tile_clicked:
                                                                await asyncio.sleep(1)  # Даём время на обработку клика
                                                                
                                                                # Задержка перед проверкой "DEATH TILE!" для корректной загрузки страницы
                                                                await asyncio.sleep(2)
                                                                
                                                                # Проверяем наличие текста "DEATH TILE!" - если есть, игра проиграна
                                                                death_tile_found = False
                                                                try:
                                                                    logger.info("Проверка наличия текста 'DEATH TILE!'...")
                                                                    
                                                                    # Пробуем разные способы поиска текста "DEATH TILE!"
                                                                    # Вариант 1: через text locator
                                                                    try:
                                                                        death_tile_text = page.locator('text=/DEATH TILE!/i').first
                                                                        is_visible = await death_tile_text.is_visible(timeout=2000)
                                                                        if is_visible:
                                                                            logger.warning("Обнаружен текст 'DEATH TILE!' - игра проиграна, Cash out не требуется")
                                                                            death_tile_found = True
                                                                    except Exception:
                                                                        # Вариант 2: через поиск по тексту в DOM
                                                                        try:
                                                                            page_text = await page.text_content()
                                                                            if page_text and "DEATH TILE!" in page_text.upper():
                                                                                logger.warning("Обнаружен текст 'DEATH TILE!' (через text_content) - игра проиграна, Cash out не требуется")
                                                                                death_tile_found = True
                                                                        except Exception:
                                                                            # Вариант 3: через evaluate
                                                                            try:
                                                                                death_tile_exists = await page.evaluate("""
                                                                                    () => {
                                                                                        const text = document.body.innerText || document.body.textContent || '';
                                                                                        return text.toUpperCase().includes('DEATH TILE!');
                                                                                    }
                                                                                """)
                                                                                if death_tile_exists:
                                                                                    logger.warning("Обнаружен текст 'DEATH TILE!' (через evaluate) - игра проиграна, Cash out не требуется")
                                                                                    death_tile_found = True
                                                                            except Exception as e:
                                                                                logger.debug(f"Не удалось проверить наличие 'DEATH TILE!' через evaluate: {e}")
                                                                except Exception as e:
                                                                    # Текст не найден - это нормально, продолжаем
                                                                    logger.debug(f"Текст 'DEATH TILE!' не найден: {e}, продолжаем проверку Cash out")
                                                                
                                                                # Если "DEATH TILE!" найден, пропускаем Cash out и переходим к следующему раунду
                                                                if death_tile_found:
                                                                    logger.info("Игра проиграна, пропускаем Cash out и переходим к следующему раунду")
                                                                    # Продолжаем цикл для следующего раунда
                                                                    await asyncio.sleep(2)  # Даём время на обработку
                                                                    # Возвращаемся на основную страницу для следующего раунда
                                                                    logger.info("Возврат на основную страницу для следующего раунда...")
                                                                    await page.goto("https://soneium.superstake.fun/", wait_until="networkidle", timeout=60000)
                                                                    await asyncio.sleep(2)  # Даём время на загрузку страницы
                                                                    
                                                                    # Проверяем наличие кнопки "Out of IP Games" после проигрыша
                                                                    out_of_ip_games_selector = 'button[data-slot="button"][aria-label="Out of IP Games"]'
                                                                    out_of_ip_found = False
                                                                    
                                                                    try:
                                                                        out_of_ip_button = page.locator(out_of_ip_games_selector).first
                                                                        is_visible = await out_of_ip_button.is_visible(timeout=2000)
                                                                        if is_visible:
                                                                            out_of_ip_found = True
                                                                    except Exception:
                                                                        pass
                                                                    
                                                                    # Альтернативная проверка по тексту
                                                                    if not out_of_ip_found:
                                                                        try:
                                                                            out_of_ip_text_selector = 'button:has-text("Out of IP Games")'
                                                                            out_of_ip_text_button = page.locator(out_of_ip_text_selector).first
                                                                            is_visible = await out_of_ip_text_button.is_visible(timeout=2000)
                                                                            if is_visible:
                                                                                out_of_ip_found = True
                                                                        except Exception:
                                                                            pass
                                                                    
                                                                    if out_of_ip_found:
                                                                        logger.warning("Out of IP Games")
                                                                        logger.info("Обнаружена кнопка 'Out of IP Games' после проигрыша, завершаем работу")
                                                                        return None  # Возвращаем None для случая "Out of IP Games"
                                                                    
                                                                    # Продолжаем цикл для следующего раунда
                                                                    logger.info(f"Раунд #{game_round} завершён (проигрыш), переходим к следующему раунду...")
                                                                    failed_attempts = 0  # Сбрасываем счетчик неудачных попыток
                                                                    
                                                                    # Рандомная задержка между играми от 10 до 30 секунд
                                                                    delay = random.randint(10, 30)
                                                                    logger.info(f"Ожидание {delay} секунд перед следующим раундом...")
                                                                    await asyncio.sleep(delay)
                                                                    
                                                                    continue  # Переходим к следующей итерации цикла игры
                                                                
                                                                # Проверяем наличие кнопки "Cash out"
                                                                logger.info("Проверка наличия кнопки 'Cash out'...")
                                                                cash_out_button_selector = 'button[data-slot="button"][aria-label="Cash out current winnings"]'
                                                                cash_out_clicked = False
                                                                
                                                                try:
                                                                    # Ждём появления кнопки с таймаутом 10 секунд
                                                                    await page.wait_for_selector(cash_out_button_selector, timeout=10000)
                                                                    
                                                                    # Проверяем, что кнопка не disabled
                                                                    cash_out_button = page.locator(cash_out_button_selector).first
                                                                    is_disabled = await cash_out_button.get_attribute('disabled')
                                                                    
                                                                    if not is_disabled:
                                                                        logger.info("Кнопка 'Cash out' найдена и активна, кликаем...")
                                                                        await cash_out_button.click()
                                                                        logger.success("Кнопка 'Cash out' нажата успешно")
                                                                        cash_out_clicked = True
                                                                        await asyncio.sleep(2)  # Даём время на открытие окна расширения
                                                                    else:
                                                                        logger.info("Кнопка 'Cash out' найдена, но не активна (disabled)")
                                                                except Exception as e:
                                                                    logger.info(f"Кнопка 'Cash out' не появилась или не найдена: {e}")
                                                                
                                                                # Если кнопка "Cash out" была нажата, обрабатываем окно расширения
                                                                if cash_out_clicked:
                                                                    # Ждём появления нового окна расширения для подтверждения транзакции
                                                                    logger.info("Ожидание нового окна расширения для подтверждения транзакции...")
                                                                    cashout_sign_page = None
                                                                    
                                                                    # Ждём появления новой страницы расширения (может открыться с задержкой)
                                                                    for attempt in range(15):  # Пробуем до 15 раз с интервалом 0.5 сек
                                                                        for existing_page in context.pages:
                                                                            # Ищем страницу расширения, которая отличается от предыдущих
                                                                            if (existing_page.url.startswith(f"chrome-extension://{extension_id}/") 
                                                                                and existing_page != extension_page 
                                                                                and existing_page != sign_page
                                                                                and existing_page != transaction_sign_page):
                                                                                cashout_sign_page = existing_page
                                                                                break
                                                                        if cashout_sign_page:
                                                                            break
                                                                        await asyncio.sleep(0.5)
                                                                    
                                                                    if not cashout_sign_page:
                                                                        logger.warning("Новое окно расширения для cashout не найдено, пробуем найти любую новую страницу расширения")
                                                                        # Пробуем найти любую новую страницу расширения
                                                                        for existing_page in context.pages:
                                                                            if (existing_page.url.startswith("chrome-extension://") 
                                                                                and existing_page != extension_page 
                                                                                and existing_page != sign_page
                                                                                and existing_page != transaction_sign_page):
                                                                                cashout_sign_page = existing_page
                                                                                break
                                                                    
                                                                    if cashout_sign_page:
                                                                        logger.info("Обработка окна подтверждения транзакции cashout...")
                                                                        
                                                                        # Кликаем на кнопку "Sign"
                                                                        sign_button_selector = 'button:has-text("Sign")'
                                                                        
                                                                        try:
                                                                            logger.info("Ожидание кнопки 'Sign' в окне подтверждения cashout...")
                                                                            await cashout_sign_page.wait_for_selector(sign_button_selector, timeout=30000)
                                                                            await cashout_sign_page.click(sign_button_selector)
                                                                            logger.success("Кнопка 'Sign' нажата успешно")
                                                                            await asyncio.sleep(1)  # Даём время на обработку
                                                                        except Exception as e:
                                                                            # Пробуем альтернативные селекторы
                                                                            logger.debug(f"Не удалось найти кнопку по селектору {sign_button_selector}, пробуем альтернативные: {e}")
                                                                            try:
                                                                                # Пробуем регистронезависимо
                                                                                sign_text_selector = 'button:has-text("Sign"), button:has-text("sign")'
                                                                                await cashout_sign_page.wait_for_selector(sign_text_selector, timeout=10000)
                                                                                await cashout_sign_page.click(sign_text_selector)
                                                                                logger.success("Кнопка 'Sign' нажата успешно (через альтернативный селектор)")
                                                                                await asyncio.sleep(1)
                                                                            except Exception as e2:
                                                                                logger.warning(f"Не удалось найти кнопку 'Sign': {e2}, продолжаем...")
                                                                        
                                                                        # Кликаем на кнопку "Confirm"
                                                                        confirm_button_selector = 'button:has-text("Confirm")'
                                                                        
                                                                        try:
                                                                            logger.info("Ожидание кнопки 'Confirm' в окне подтверждения cashout...")
                                                                            await cashout_sign_page.wait_for_selector(confirm_button_selector, timeout=30000)
                                                                            await cashout_sign_page.click(confirm_button_selector)
                                                                            logger.success("Кнопка 'Confirm' нажата успешно")
                                                                            await asyncio.sleep(1)  # Даём время на обработку
                                                                        except Exception as e:
                                                                            # Пробуем альтернативные селекторы
                                                                            logger.debug(f"Не удалось найти кнопку по селектору {confirm_button_selector}, пробуем альтернативные: {e}")
                                                                            try:
                                                                                # Пробуем регистронезависимо
                                                                                confirm_text_selector = 'button:has-text("Confirm"), button:has-text("confirm")'
                                                                                await cashout_sign_page.wait_for_selector(confirm_text_selector, timeout=10000)
                                                                                await cashout_sign_page.click(confirm_text_selector)
                                                                                logger.success("Кнопка 'Confirm' нажата успешно (через альтернативный селектор)")
                                                                                await asyncio.sleep(1)
                                                                            except Exception as e2:
                                                                                logger.warning(f"Не удалось найти кнопку 'Confirm': {e2}")
                                                            
                                                        except Exception as e:
                                                            logger.warning(f"Ошибка при ожидании активных кнопок: {e}, продолжаем...")
                                                        
                                                        # После завершения раунда проверяем "Out of IP Games" и продолжаем цикл
                                                        await asyncio.sleep(2)  # Даём время на завершение раунда
                                                        
                                                        # Возвращаемся на основную страницу для следующего раунда
                                                        logger.info("Возврат на основную страницу для следующего раунда...")
                                                        await page.goto("https://soneium.superstake.fun/", wait_until="networkidle", timeout=60000)
                                                        await asyncio.sleep(2)  # Даём время на загрузку страницы
                                                        
                                                        # Проверяем наличие кнопки "Out of IP Games" после раунда
                                                        out_of_ip_games_selector = 'button[data-slot="button"][aria-label="Out of IP Games"]'
                                                        out_of_ip_found = False
                                                        
                                                        try:
                                                            out_of_ip_button = page.locator(out_of_ip_games_selector).first
                                                            is_visible = await out_of_ip_button.is_visible(timeout=2000)
                                                            if is_visible:
                                                                out_of_ip_found = True
                                                        except Exception:
                                                            pass
                                                        
                                                        # Альтернативная проверка по тексту
                                                        if not out_of_ip_found:
                                                            try:
                                                                out_of_ip_text_selector = 'button:has-text("Out of IP Games")'
                                                                out_of_ip_text_button = page.locator(out_of_ip_text_selector).first
                                                                is_visible = await out_of_ip_text_button.is_visible(timeout=2000)
                                                                if is_visible:
                                                                    out_of_ip_found = True
                                                            except Exception:
                                                                pass
                                                        
                                                        if out_of_ip_found:
                                                            logger.warning("Out of IP Games")
                                                            logger.info("Обнаружена кнопка 'Out of IP Games' после раунда, завершаем работу")
                                                            return None  # Возвращаем None для случая "Out of IP Games"
                                                        
                                                        # Продолжаем цикл для следующего раунда
                                                        logger.info(f"Раунд #{game_round} завершён, переходим к следующему раунду...")
                                                        failed_attempts = 0  # Сбрасываем счетчик неудачных попыток при успешном раунде
                                                        
                                                        # Рандомная задержка между играми от 10 до 30 секунд
                                                        delay = random.randint(10, 30)
                                                        logger.info(f"Ожидание {delay} секунд перед следующим раундом...")
                                                        await asyncio.sleep(delay)
                                                        
                                                        continue
                                                else:
                                                    # Если "Play with IP" не была нажата, проверяем "Out of IP Games" и продолжаем цикл
                                                    logger.warning("Не удалось нажать кнопку 'Play with IP'")
                                                    await asyncio.sleep(2)
                                                    
                                                    out_of_ip_games_selector = 'button[data-slot="button"][aria-label="Out of IP Games"]'
                                                    out_of_ip_found = False
                                                    
                                                    try:
                                                        out_of_ip_button = page.locator(out_of_ip_games_selector).first
                                                        is_visible = await out_of_ip_button.is_visible(timeout=2000)
                                                        if is_visible:
                                                            out_of_ip_found = True
                                                    except Exception:
                                                        pass
                                                    
                                                    if not out_of_ip_found:
                                                        try:
                                                            out_of_ip_text_selector = 'button:has-text("Out of IP Games")'
                                                            out_of_ip_text_button = page.locator(out_of_ip_text_selector).first
                                                            is_visible = await out_of_ip_text_button.is_visible(timeout=2000)
                                                            if is_visible:
                                                                out_of_ip_found = True
                                                        except Exception:
                                                            pass
                                                    
                                                    if out_of_ip_found:
                                                        logger.warning("Out of IP Games")
                                                        logger.info("Обнаружена кнопка 'Out of IP Games', завершаем работу")
                                                        return None
                                                    
                                                    logger.info(f"Ошибка в раунде #{game_round}, переходим к следующему раунду...")
                                                    continue
                                    
                                except Exception as e:
                                    logger.error(f"Не удалось найти элемент 'Connect' в расширении: {e}")
                                    return False
                            else:
                                logger.error("Не удалось найти страницу расширения кошелька")
                                return False

            finally:
                # В CDP-режиме не закрываем браузер/контекст — ими управляет AdsPower
                await playwright.stop()

        except Exception as e:
            logger.error(f"Ошибка при подключении к Soneium: {e}")
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

    def check_api_status(self) -> bool:
        """
        Проверяет доступность AdsPower API.
        Пытается выполнить простой запрос для проверки подключения.

        Returns:
            True если API доступен, False в противном случае
        """
        try:
            # Пробуем простой запрос к API v2 - проверяем список профилей
            # Используем v2 эндпоинт для проверки
            result = self._make_request("GET", "/api/v2/browser-profile/list")
            logger.info("AdsPower API доступен")
            return True
        except Exception as e:
            # Если не получилось, просто логируем ошибку
            logger.warning(f"Не удалось проверить статус API: {e}")
            # Возвращаем True, чтобы не блокировать работу - проверка будет при реальных запросах
            return True

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
        self, wait_time: int = 20, import_wallet: bool = True, key_index: int = 0, wallet_password: str = "Password123", use_proxy: bool = True, target_required: int = 20, check_progress: bool = True
    ) -> bool:
        """
        Выполняет полный цикл: создание профиля -> открытие браузера -> импорт кошелька -> 
        подключение к Soneium -> ожидание -> закрытие -> удаление.

        Args:
            wait_time: Время ожидания в секундах (по умолчанию 20)
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
                    completed, required = _extract_cashorcrash_progress(profile)
                    
                    target = int(target_required)
                    done = min(int(completed), target)
                    
                    logger.info(f"{wallet_address} CashOrCrash {done}/{target}")
                    
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
                    # Согласно документации AdsPower: data['data']['ws']['puppeteer']
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
                        
                        # Переходим на страницу Soneium и нажимаем Connect
                        logger.info("Переход на Soneium и подключение кошелька...")
                        connection_result = asyncio.run(self._connect_to_soneium_via_cdp(cdp_endpoint=cdp_endpoint))
                        if connection_result is True:
                            logger.success("Подключение к Soneium выполнено успешно")
                        elif connection_result is None:
                            # Out of IP Games - это не ошибка, просто завершаем работу
                            logger.info("Обнаружено 'Out of IP Games', завершаем выполнение цикла")
                            # Очищаем ресурсы перед выходом
                            try:
                                self.stop_browser(profile_id)
                                self.delete_profile(profile_id, clear_cache=True)
                            except Exception as e:
                                logger.warning(f"Ошибка при очистке ресурсов: {e}")
                            return  # Завершаем выполнение цикла
                        else:
                            logger.warning("Не удалось подключиться к Soneium, но продолжаем выполнение цикла")
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
        browser_manager = CashOrCrash(api_key=api_key)
        
        target_required = 20  # Целевое количество транзакций для Cash or Crash
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
                    if is_wallet_completed(wallet_address, "cashorcrash", QUESTS_DB_PATH):
                        logger.info(f"[SKIP DB] {wallet_address} CashOrCrash уже выполнен")
                        wallets_completed += 1
                        continue
                    
                    # Проверяем прогресс перед выполнением
                    try:
                        profile = _fetch_portal_bonus_profile(wallet_address)
                        completed, required = _extract_cashorcrash_progress(profile)
                        
                        done = min(int(completed), target)
                        
                        print(f"{wallet_address} CashOrCrash {done}/{target}")
                        
                        # Если уже достигли цели - сохраняем в БД и пропускаем
                        if done >= target:
                            mark_wallet_completed(wallet_address, "cashorcrash", done, target, QUESTS_DB_PATH)
                            logger.info(f"[SKIP] address={wallet_address} already {done}/{target}")
                            wallets_completed += 1
                            continue
                    except Exception as e:
                        # При ошибке проверки прогресса продолжаем выполнение
                        logger.warning(f"Ошибка при проверке прогресса: {e}, продолжаем выполнение...")
                    
                    # Выполняем цикл
                    cycle_result = browser_manager.run_full_cycle(
                        wait_time=20, 
                        key_index=key_index,
                        target_required=target_required,
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


def main() -> None:
    """
    Главная функция для запуска модуля напрямую.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="CashOrCrash - создание временного браузера через AdsPower API"
    )
    parser.add_argument(
        "--api-key",
        help="API ключ для AdsPower (если не указан, загружается из файла)",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=50325,
        help="Порт API (по умолчанию 50325)",
    )
    parser.add_argument(
        "--wait-time",
        type=int,
        default=20,
        help="Время ожидания в секундах (по умолчанию 20)",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Не использовать прокси (по умолчанию используется случайный прокси)",
    )

    args = parser.parse_args()

    # Настройка логирования
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        level="INFO",
    )

    # Загрузка API ключа (из аргумента или файла)
    if args.api_key:
        api_key = args.api_key
    else:
        try:
            api_key = load_adspower_api_key()
            logger.info("API ключ загружен из файла")
        except (FileNotFoundError, ValueError) as e:
            logger.error(f"{e}")
            raise SystemExit(1)

    # Создание экземпляра и запуск цикла
    browser_manager = CashOrCrash(api_key=api_key, api_port=args.api_port)
    browser_manager.run_full_cycle(wait_time=args.wait_time, use_proxy=not args.no_proxy)


if __name__ == "__main__":
    main()

