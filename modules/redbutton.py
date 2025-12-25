#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import requests
from loguru import logger
from web3 import Web3

# Позволяет запускать файл напрямую: `python modules/redbutton.py`
# (иначе sys.path указывает на папку modules/, и `import modules.*` не находится).
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
    # Fallback если модуль не найден
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
            # Пропускаем комментарии и пустые строки
            if line and not line.startswith("#"):
                # Проверяем формат приватного ключа (64 символа hex)
                if re.match(r"^0x[a-fA-F0-9]{64}$", line):
                    keys.append(line)
                elif re.match(r"^[a-fA-F0-9]{64}$", line):
                    keys.append("0x" + line)
                else:
                    print(f"⚠️ Неверный формат ключа: {line[:20]}...")

    return keys


# === Конфиг сети/контракта ===
# RPC и chainId заданы пользователем:
# - RPC: https://soneium-rpc.publicnode.com (источник: https://soneium-rpc.publicnode.com)
# - chainId: 1868
RPC_URL_DEFAULT = "https://soneium-rpc.publicnode.com"
CHAIN_ID = 1868

CONTRACT_ADDRESS = Web3.to_checksum_address("0x39B4a19C687a3b9530EFE28752a81E41FdD398fa")

# Blockscout
BLOCKSCOUT_TX_BASE = "https://soneium.blockscout.com/tx"

# Portal API (квесты/прогресс)
PORTAL_PROFILE_URL = "https://portal.soneium.org/api/profile/bonus-dapp"

# ABI (минимально необходимое: drawItem). Если понадобится, можно расширить.
CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "uint8", "name": "_gachaTypeIndex", "type": "uint8"},
            {"internalType": "uint256", "name": "_deadline", "type": "uint256"},
            {"internalType": "bytes", "name": "_permitSig", "type": "bytes"},
        ],
        "name": "drawItem",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function",
    }
]


PROXY_FILE = PROJECT_ROOT / "proxy.txt"
def _setup_logger(level: str = "INFO", log_file: str = "") -> None:
    """
    Логгер (loguru):
    - логирует в stderr с форматом как в CashOrCrash.py
    - при необходимости можно включить лог в файл через log_file
    """
    # Убираем дефолтный sink
    logger.remove()

    # Настраиваем логирование в stderr
    lvl = (level or "INFO").upper()
    logger.add(
        sys.stderr,
        format="{time:YYYY-MM-DD HH:mm:ss} | <level>{level}</level> | {message}",
        level=lvl,
        colorize=True,
    )

    # Если нужен файл — добавляем дополнительный sink
    if log_file:
        logger.add(
            log_file,
            level=lvl,
            rotation="2 MB",
            retention=3,
            encoding="utf-8",
            backtrace=True,
            diagnose=False,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
        )


def tx_url(tx_hash_hex: str) -> str:
    return f"{BLOCKSCOUT_TX_BASE}/{tx_hash_hex}"


def _pick_random_proxy_from_file() -> Optional["ProxyEntry"]:
    proxies = load_proxies()
    if not proxies:
        return None
    return random.choice(proxies)


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
            logger.debug(
                "[PORTAL] attempt {}/{} proxy={} err={}",
                attempt,
                attempts,
                (p.safe_label if p else "none"),
                e,
            )
            # небольшой джиттер перед повтором
            time.sleep(random.uniform(0.4, 1.2))

    raise RuntimeError(f"Portal недоступен после {attempts} попыток (прокси ротировались): {last_err}")


def _extract_redbutton_progress(profile: list[dict[str, Any]]) -> tuple[int, int]:
    """
    Возвращает (completed, required) для квеста RedButton.
    Ищем объект с id вида redbutton_* (например, redbutton_5).
    """
    candidates: list[dict[str, Any]] = []
    for item in profile:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id", "")).lower()
        if item_id.startswith("redbutton"):
            candidates.append(item)

    if not candidates:
        raise RuntimeError("В ответе portal не найден квест redbutton_*")

    candidates.sort(key=lambda x: int(x.get("week", 0) or 0), reverse=True)
    rb = candidates[0]
    quests = rb.get("quests") or []
    if not isinstance(quests, list) or not quests:
        raise RuntimeError("В redbutton_* отсутствует quests[]")

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
    if not PROXY_FILE.exists():
        return []
    proxies: list[ProxyEntry] = []
    for raw in PROXY_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        p = _parse_proxy_line(raw)
        if p:
            proxies.append(p)
    return proxies


def _make_web3(rpc_url: str, proxy: Optional[ProxyEntry]) -> Web3:
    request_kwargs: dict[str, Any] = {"timeout": 60}
    if proxy is not None:
        request_kwargs["proxies"] = {"http": proxy.http_url, "https": proxy.http_url}
    return Web3(Web3.HTTPProvider(rpc_url, request_kwargs=request_kwargs))


def _rpc_sanity_check(w3: Web3) -> None:
    if not w3.is_connected():
        raise RuntimeError("RPC недоступен (w3.is_connected() == False)")
    # Проверяем chainId (важно для подписи)
    chain_id = int(w3.eth.chain_id)
    if chain_id != CHAIN_ID:
        raise RuntimeError(f"Неожиданный chainId от RPC: {chain_id} (ожидали {CHAIN_ID})")


def _pick_proxy(mode: str, proxy_attempts: int) -> Optional[ProxyEntry]:
    mode = (mode or "none").strip().lower()
    if mode in ("none", "off", "no"):
        return None

    proxies = load_proxies()
    if not proxies:
        raise RuntimeError(f"proxy.txt не найден или пустой: {PROXY_FILE}")

    if mode in ("random", "rand"):
        return random.choice(proxies)

    if mode in ("working", "check", "best"):
        remaining = proxies[:]
        attempts = min(proxy_attempts, len(remaining))
        for i in range(attempts):
            p = random.choice(remaining)
            remaining.remove(p)
            try:
                w3 = _make_web3(RPC_URL_DEFAULT, proxy=p)
                _rpc_sanity_check(w3)
                logger.debug("[PROXY] ok: {}", p.safe_label)
                return p
            except Exception:
                logger.debug("[PROXY] bad: {} ({}/{})", p.safe_label, i + 1, attempts)
        raise RuntimeError(f"Не удалось подобрать рабочий прокси за {attempts} попыток")

    raise RuntimeError(f"Неизвестный режим proxy-mode: {mode!r} (ожидается none|random|working)")


def _suggest_fees(w3: Web3) -> dict[str, int]:
    """
    Возвращает либо EIP-1559 поля (maxFeePerGas/maxPriorityFeePerGas), либо gasPrice.
    """
    latest = w3.eth.get_block("latest")
    base_fee = latest.get("baseFeePerGas")
    if base_fee is None:
        return {"gasPrice": int(w3.eth.gas_price)}

    # maxPriorityFeePerGas может отсутствовать в некоторых RPC — делаем мягкий фоллбэк.
    try:
        prio = int(getattr(w3.eth, "max_priority_fee", 0) or 0)
    except Exception:
        prio = 0
    if prio <= 0:
        # Консервативный дефолт
        prio = Web3.to_wei(1, "gwei")

    base_fee_i = int(base_fee)
    # maxFee = 2*baseFee + priority (классическая стратегия)
    max_fee = base_fee_i * 2 + prio
    return {"maxFeePerGas": int(max_fee), "maxPriorityFeePerGas": int(prio)}


def build_draw_item_calldata(
    w3: Web3,
    gacha_type_index: int,
    deadline: int,
    permit_sig_hex: str,
) -> str:
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    permit_bytes = bytes.fromhex(permit_sig_hex[2:]) if permit_sig_hex and permit_sig_hex != "0x" else b""
    # Возвращаем hex-строку calldata вида "0x...."
    return contract.encodeABI(fn_name="drawItem", args=[gacha_type_index, deadline, permit_bytes])  # type: ignore[return-value]


def send_draw_item_tx(
    *,
    private_key: str,
    rpc_url: str,
    proxy: Optional[ProxyEntry],
    gacha_type_index: int = 0,
    deadline_seconds_from_now: int = 3600,
    permit_sig_hex: str = "0x",
    value_wei: int = 0,
    gas_limit: Optional[int] = None,
    dry_run: bool = False,
    wait_receipt: bool = True,
    receipt_timeout_sec: int = 180,
) -> str:
    w3 = _make_web3(rpc_url, proxy=proxy)
    _rpc_sanity_check(w3)

    acct = w3.eth.account.from_key(private_key)
    from_addr = acct.address

    deadline = int(time.time()) + int(deadline_seconds_from_now)

    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    permit_bytes = bytes.fromhex(permit_sig_hex[2:]) if permit_sig_hex and permit_sig_hex != "0x" else b""

    nonce = int(w3.eth.get_transaction_count(from_addr, "pending"))
    fees = _suggest_fees(w3)

    tx: dict[str, Any] = {
        "chainId": CHAIN_ID,
        "from": from_addr,
        "to": CONTRACT_ADDRESS,
        "nonce": nonce,
        "value": int(value_wei),
    }
    tx.update(fees)

    # data: drawItem(0, now+1h, 0x)
    # selector у функции: 0x2ff92028 (для справки; web3 кодирует сам)
    fn = contract.functions.drawItem(int(gacha_type_index), int(deadline), permit_bytes)
    call_data = fn._encode_transaction_data()  # noqa: SLF001 (web3 internal)

    if gas_limit is None:
        try:
            # ВАЖНО: для contract fn estimate_gas нельзя передавать `to`
            # (адрес контракта уже “зашит” в объекте функции).
            estimate_tx: dict[str, Any] = {"from": from_addr, "value": int(value_wei)}
            # Иногда помогает передать fee-поля (не обязательно, но безвредно)
            for k in ("gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"):
                if k in tx:
                    estimate_tx[k] = tx[k]

            estimated = int(fn.estimate_gas(estimate_tx))
            # небольшой буфер
            gas_limit = int(estimated * 1.2) + 10_000
        except Exception as e:
            raise RuntimeError(f"Не удалось оценить gas для drawItem(): {e}") from e

    tx["gas"] = int(gas_limit)
    tx["data"] = call_data

    if dry_run:
        # eth_call для проверки, что не ревертит на текущем состоянии
        try:
            call_tx = {k: v for k, v in tx.items() if k in ("from", "to", "data", "value", "gas")}
            w3.eth.call(call_tx)
            return "DRY_RUN_OK"
        except Exception as e:
            raise RuntimeError(f"DRY_RUN revert/ошибка: {e}") from e

    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    tx_hash_hex = tx_hash.hex()

    if not wait_receipt:
        return tx_hash_hex

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=receipt_timeout_sec)
    status = int(getattr(receipt, "status", 0) or 0)
    if status != 1:
        raise RuntimeError(f"Транзакция в receipt со статусом {status}: {tx_hash_hex}")
    return tx_hash_hex


async def _process_wallet(
    *,
    pk: str,
    key_index: int,
    rpc_url: str,
    proxy: Optional[ProxyEntry],
    gacha_type_index: int,
    deadline_seconds_from_now: int,
    permit_sig_hex: str,
    value_wei: int,
    gas_limit: Optional[int],
    dry_run: bool,
    wait_receipt: bool,
    target_required: int,
    delay_min_sec: int,
    delay_max_sec: int,
) -> tuple[str, int, bool]:
    """
    Обрабатывает один кошелек: проверяет прогресс и отправляет транзакцию если нужно.
    Возвращает (address, current_progress, needs_more) - нужен ли еще прогресс для этого кошелька.
    """
    addr = ""
    try:
        # Адрес кошелька
        addr = Web3.to_checksum_address(_make_web3(rpc_url, proxy=None).eth.account.from_key(pk).address)

        # Проверяем БД перед запросом к Portal API
        target = int(target_required)
        if is_wallet_completed(addr, "redbutton", QUESTS_DB_PATH):
            logger.info("{} RedButton [SKIP DB] уже выполнен", addr)
            return addr, target, False

        # Проверяем прогресс RedButton через portal (строго через случайный прокси из proxy.txt)
        profile = _fetch_portal_bonus_profile(addr)
        completed_raw, _required_api = _extract_redbutton_progress(profile)

        # Нас интересует именно добивка до 15 (или до target_required)
        done = min(int(completed_raw), target)

        # Логируем прогресс "сколько из скольки"
        logger.info("{} RedButton {}/{}", addr, done, target)

        # Если уже достигли цели - сохраняем в БД и пропускаем
        if done >= target:
            mark_wallet_completed(addr, "redbutton", done, target, QUESTS_DB_PATH)
            return addr, done, False

        # Dry-run: не отправляем транзы, просто проверяем, что портал отдаёт данные
        if dry_run:
            return addr, done, True  # В dry-run всегда возвращаем True, чтобы продолжить цикл

        # Отправляем транзакцию
        tx_hash = await asyncio.to_thread(
            send_draw_item_tx,
            private_key=pk,
            rpc_url=rpc_url,
            proxy=proxy,  # RPC-прокси (если включили proxy-mode)
            gacha_type_index=gacha_type_index,
            deadline_seconds_from_now=deadline_seconds_from_now,
            permit_sig_hex=permit_sig_hex,
            value_wei=value_wei,
            gas_limit=gas_limit,
            dry_run=False,
            wait_receipt=wait_receipt,
        )

        # Логируем ссылку на транзакцию
        logger.success("{}", tx_url(tx_hash))

        # После отправки: случайная задержка
        lo = int(delay_min_sec)
        hi = int(delay_max_sec)
        if hi < lo:
            hi = lo
        delay = random.randint(lo, hi)
        logger.info("[SLEEP] {}s", delay)
        await asyncio.sleep(delay)

        # После отправки транзакции прогресс увеличится, но мы не знаем точно на сколько
        # Возвращаем True, чтобы проверить прогресс в следующей итерации
        return addr, done, True

    except Exception as e:
        # Не валим весь прогон из-за одного плохого прокси/кошелька
        error_addr = addr if addr else f"key#{key_index}"
        logger.error("{} portal_error: {}", error_addr, e)
        # При ошибке возвращаем True, чтобы попробовать еще раз в следующей итерации
        return error_addr, 0, True


async def run(
    *,
    rpc_url: str = RPC_URL_DEFAULT,
    key_index: Optional[int] = 0,
    all_keys: bool = False,
    proxy_mode: str = "none",
    proxy_attempts: int = 10,
    gacha_type_index: int = 0,
    deadline_seconds_from_now: int = 3600,
    permit_sig_hex: str = "0x",
    value_wei: int = 0,
    gas_limit: Optional[int] = None,
    dry_run: bool = False,
    wait_receipt: bool = True,
    target_required: int = 15,
    delay_min_sec: int = 15,
    delay_max_sec: int = 60,
    max_txs_per_wallet: int = 15,
) -> None:
    """
    Программный модуль RedButton:
    отправляет tx в контракт Soneium на метод drawItem(uint8,uint256,bytes).
    Обрабатывает кошельки в случайном порядке до тех пор, пока все не достигнут target_required транзакций.
    """
    _setup_logger()
    
    # Инициализация БД для квестов
    try:
        init_quests_database(QUESTS_DB_PATH)
        logger.debug("База данных квестов инициализирована")
    except Exception as e:
        logger.warning(f"Не удалось инициализировать БД квестов: {e}, продолжаем без БД")
    
    keys = load_private_keys()
    if not keys:
        raise RuntimeError("Не найдено действительных приватных ключей в keys.txt")

    proxy = _pick_proxy(proxy_mode, proxy_attempts=proxy_attempts)
    if proxy:
        logger.debug("[PROXY] using: {}", proxy.safe_label)

    target = int(target_required)
    iteration = 0

    # Основной цикл: продолжаем пока есть кошельки, которым нужны транзакции
    while True:
        iteration += 1
        logger.debug("[ITERATION] starting iteration #{}", iteration)

        # Создаем список индексов и перемешиваем их случайно на каждой итерации
        indices = list(range(len(keys)))
        random.shuffle(indices)

        wallets_need_progress = 0
        wallets_completed = 0

        # Обрабатываем каждый кошелек
        for i in indices:
            pk = keys[i]
            addr, current_progress, needs_more = await _process_wallet(
                pk=pk,
                key_index=i,
                rpc_url=rpc_url,
                proxy=proxy,
                gacha_type_index=gacha_type_index,
                deadline_seconds_from_now=deadline_seconds_from_now,
                permit_sig_hex=permit_sig_hex,
                value_wei=value_wei,
                gas_limit=gas_limit,
                dry_run=dry_run,
                wait_receipt=wait_receipt,
                target_required=target,
                delay_min_sec=delay_min_sec,
                delay_max_sec=delay_max_sec,
            )

            if needs_more:
                wallets_need_progress += 1
            else:
                wallets_completed += 1

        # Если все кошельки достигли цели - завершаем
        if wallets_need_progress == 0:
            logger.info("[COMPLETE] all wallets reached target {}/{}", target, target)
            break

        # Логируем статистику итерации
        logger.debug(
            "[ITERATION] #{} completed: {} wallets need progress, {} wallets completed",
            iteration,
            wallets_need_progress,
            wallets_completed,
        )


if __name__ == "__main__":
    # CLI-аргументы убраны по запросу пользователя.
    # Запуск: `python modules/redbutton.py` или через `python main.py`.
    _setup_logger()
    asyncio.run(run())


