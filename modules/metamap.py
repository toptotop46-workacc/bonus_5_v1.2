#!/usr/bin/env python3
from __future__ import annotations

import random
import sys
import time
from pathlib import Path
from typing import Optional

from loguru import logger
from web3 import Web3

# Позволяет запускать файл напрямую: `python modules/metamap.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    root_s = str(PROJECT_ROOT)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)

# Импорт db_utils
from modules.db_utils import (
    init_quests_database,
    is_wallet_completed,
    mark_wallet_completed,
    QUESTS_DB_PATH,
)

# Импорт функций загрузки
from modules.mint4season import load_private_key, load_all_keys

# ==================== КОНФИГУРАЦИЯ ====================
METAMAP_CONTRACT_ADDRESS = "0xc09286a6f0687c769579ac38dd682390a48d0092"
MAX_FEE = 0.000025  # ether
RPC_URL_DEFAULT = "https://soneium-rpc.publicnode.com"
CHAIN_ID = 1868
MINT_QUANTITY = 1

# Константы для задержки между кошельками
MIN_DELAY_MINUTES = 1   # Минимальная задержка: 1 минута
MAX_DELAY_MINUTES = 100 # Максимальная задержка: 100 минут
DEFAULT_DELAY_MINUTES = 5  # Значение по умолчанию

# ISO коды стран (ISO 3166-1 alpha-2)
ISO_CODES = [
    "US", "GB", "DE", "FR", "JP", "CN", "KR", "IN", "BR", "RU",
    "CA", "AU", "IT", "ES", "MX", "ID", "NL", "SA", "TR", "CH",
    "SE", "NO", "DK", "FI", "PL", "BE", "AT", "GR", "PT", "IE",
    "NZ", "SG", "MY", "TH", "VN", "PH", "BD", "PK", "AE", "IL",
    "EG", "ZA", "AR", "CL", "CO", "PE", "VE", "EC", "UY", "PY",
    "BO", "CR", "PA", "GT", "HN", "DO", "JM", "TT", "BB", "BS",
    "IS", "LU", "MT", "CY", "EE", "LV", "LT", "SI", "SK", "CZ",
    "HU", "RO", "BG", "HR", "RS", "BA", "MK", "AL", "ME", "XK",
]

# ==================== ABI КОНТРАКТА ====================
METAMAP_ABI = [
    {
        "inputs": [],
        "name": "fee",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "quantity", "type": "uint256"},
            {"internalType": "string", "name": "iso", "type": "string"}
        ],
        "name": "mint",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

# ==================== ФУНКЦИИ УТИЛИТЫ ====================

def format_eth(amount: float, max_decimals: int = 18) -> str:
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


def get_contract_fee(contract) -> float:
    """
    Получает текущую fee из контракта в ETH.
    
    Args:
        contract: Контракт MetaMap
    
    Returns:
        Fee в ETH как float
    """
    fee_wei = contract.functions.fee().call()
    return float(Web3.from_wei(fee_wei, "ether"))


def check_fee_safety(contract) -> bool:
    """
    Проверяет, что fee не превышает MAX_FEE.
    
    Args:
        contract: Контракт MetaMap
    
    Returns:
        True если fee безопасна, False если превышает MAX_FEE
    """
    fee = get_contract_fee(contract)
    if fee > MAX_FEE:
        logger.error(f"Fee контракта ({format_eth(fee)} ETH) превышает максимально допустимую ({format_eth(MAX_FEE)} ETH)")
        return False
    return True


def get_random_iso() -> str:
    """
    Возвращает случайный ISO код из списка.
    
    Returns:
        Случайный ISO код (2 символа)
    """
    return random.choice(ISO_CODES)


def check_nft_balance(address: str, contract) -> int:
    """
    Проверяет баланс NFT на кошельке.
    
    Args:
        address: Адрес кошелька
        contract: Контракт MetaMap
    
    Returns:
        Количество NFT на кошельке
    """
    return contract.functions.balanceOf(Web3.to_checksum_address(address)).call()


def get_delay_minutes_from_user() -> int:
    """
    Запрашивает у пользователя задержку в минутах (целое число от 1 до 100).
    
    Returns:
        Задержка в минутах
    """
    print("\n" + "=" * 60)
    print("Настройка задержки между минтингом кошельков")
    print("=" * 60)
    print(f"Укажите задержку в МИНУТАХ (целое число от {MIN_DELAY_MINUTES} до {MAX_DELAY_MINUTES})")
    print("=" * 60)
    
    while True:
        try:
            user_input = input(f"Задержка (минуты, {MIN_DELAY_MINUTES}-{MAX_DELAY_MINUTES}): ").strip()
            
            if not user_input:
                print("❌ Введите число. Попробуйте снова.")
                continue
            
            delay_minutes = int(user_input)
            
            if delay_minutes < MIN_DELAY_MINUTES:
                print(f"❌ Минимальная задержка: {MIN_DELAY_MINUTES} минута. Попробуйте снова.")
                continue
            
            if delay_minutes > MAX_DELAY_MINUTES:
                print(f"❌ Максимальная задержка: {MAX_DELAY_MINUTES} минут. Попробуйте снова.")
                continue
            
            return delay_minutes
            
        except ValueError:
            print("❌ Неверный формат. Введите целое число (например: 5).")
            continue
        except (KeyboardInterrupt, EOFError):
            # Если пользователь прервал ввод - используем значение по умолчанию
            print(f"\nИспользуется значение по умолчанию: {DEFAULT_DELAY_MINUTES} минут")
            return DEFAULT_DELAY_MINUTES


def simulate_mint_transaction(
    contract,
    address: str,
    iso: str,
    fee_wei: int,
    w3
) -> tuple[bool, Optional[str]]:
    """
    Симулирует транзакцию минтинга перед отправкой.
    
    Args:
        contract: Контракт MetaMap
        address: Адрес кошелька
        iso: ISO код
        fee_wei: Комиссия в Wei
        w3: Web3 экземпляр
    
    Returns:
        (success: bool, error_message: Optional[str])
        success: True если симуляция прошла успешно
        error_message: Сообщение об ошибке, если симуляция не прошла
    """
    try:
        # Симулируем вызов функции mint через call()
        # Это проверит, что транзакция не revert'нется
        contract.functions.mint(MINT_QUANTITY, iso).call({
            'from': address,
            'value': fee_wei
        })
        logger.debug(f"Симуляция успешна для ISO: {iso}")
        return True, None
    except Exception as e:
        error_msg = str(e)
        logger.debug(f"Симуляция не прошла для ISO {iso}: {error_msg}")
        return False, error_msg


def find_working_iso_code(
    contract,
    address: str,
    fee_wei: int,
    w3,
    max_attempts: int = 20
) -> tuple[Optional[str], int]:
    """
    Ищет рабочий ISO код, пробуя разные варианты до успешной симуляции.
    
    Args:
        contract: Контракт MetaMap
        address: Адрес кошелька
        fee_wei: Комиссия в Wei
        w3: Web3 экземпляр
        max_attempts: Максимальное количество попыток
    
    Returns:
        (iso_code: Optional[str], attempts: int)
        iso_code: Найденный рабочий ISO код или None, если не найден
        attempts: Количество попыток
    """
    logger.info(f"Поиск рабочего ISO кода (максимум {max_attempts} попыток)...")
    
    # Перемешиваем список ISO кодов для случайного выбора
    available_iso_codes = ISO_CODES.copy()
    random.shuffle(available_iso_codes)
    
    attempts = 0
    tried_iso_codes = set()
    
    for attempt in range(max_attempts):
        attempts += 1
        
        # Выбираем случайный ISO код из доступных
        # Если уже пробовали все - перемешиваем заново
        if len(tried_iso_codes) >= len(available_iso_codes):
            logger.warning("Все ISO коды были проверены, перемешиваем заново...")
            tried_iso_codes.clear()
            random.shuffle(available_iso_codes)
        
        # Выбираем ISO код, который еще не пробовали
        iso = None
        for candidate_iso in available_iso_codes:
            if candidate_iso not in tried_iso_codes:
                iso = candidate_iso
                break
        
        if iso is None:
            # Если почему-то не нашли - берем случайный
            iso = random.choice(available_iso_codes)
        
        tried_iso_codes.add(iso)
        logger.debug(f"Попытка {attempts}/{max_attempts}: проверка ISO кода {iso}...")
        
        # Симулируем транзакцию
        sim_success, sim_error = simulate_mint_transaction(
            contract=contract,
            address=address,
            iso=iso,
            fee_wei=fee_wei,
            w3=w3
        )
        
        if sim_success:
            logger.success(f"✅ Найден рабочий ISO код: {iso} (попытка {attempts})")
            return iso, attempts
        else:
            logger.debug(f"❌ ISO код {iso} не прошел симуляцию: {sim_error}")
    
    # Если не нашли рабочий ISO код
    logger.error(f"Не удалось найти рабочий ISO код за {max_attempts} попыток")
    return None, attempts


def mint_metamap_nft(
    private_key: str,
    iso: Optional[str] = None,
    rpc_url: str = RPC_URL_DEFAULT,
    auto_find_iso: bool = True
) -> dict:
    """
    Минтит 1 NFT с указанным ISO кодом или автоматически находит рабочий.
    
    Args:
        private_key: Приватный ключ кошелька
        iso: ISO код (если None и auto_find_iso=True, будет найден автоматически)
        rpc_url: URL RPC ноды
        auto_find_iso: Автоматически искать рабочий ISO код, если указанный не работает
    
    Returns:
        dict с результатом:
        {
            'success': bool,
            'tx_hash': str или None,
            'error': str или None,
            'iso_used': str,
            'iso_attempts': int  # Количество попыток подбора ISO
        }
    """
    iso_attempts = 0
    final_iso = iso
    
    try:
        # 1. Подключение к RPC
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise RuntimeError("RPC недоступен")
        
        # 2. Создание аккаунта и контракта
        account = w3.eth.account.from_key(private_key)
        address = account.address
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(METAMAP_CONTRACT_ADDRESS),
            abi=METAMAP_ABI
        )
        
        # 3. Проверка fee контракта
        fee_wei = contract.functions.fee().call()
        fee_eth = float(Web3.from_wei(fee_wei, "ether"))
        if fee_eth > MAX_FEE:
            raise ValueError(f"Fee {format_eth(fee_eth)} ETH превышает MAX_FEE {format_eth(MAX_FEE)} ETH")
        
        logger.info(f"Fee контракта: {format_eth(fee_eth)} ETH")
        
        # 4. Проверка баланса ETH
        balance_wei = w3.eth.get_balance(address)
        balance_eth = float(Web3.from_wei(balance_wei, "ether"))
        required_eth = fee_eth * MINT_QUANTITY
        
        if balance_eth < required_eth:
            raise ValueError(
                f"Недостаточно ETH: баланс {format_eth(balance_eth)} ETH < требуется {format_eth(required_eth)} ETH"
            )
        
        logger.info(f"Баланс ETH: {format_eth(balance_eth)} ETH, требуется: {format_eth(required_eth)} ETH")
        
        # 5. Определение ISO кода
        if final_iso is None:
            # Если ISO не указан - выбираем случайный
            final_iso = get_random_iso()
            logger.info(f"Выбран случайный ISO код: {final_iso}")
        
        # 6. СИМУЛЯЦИЯ ТРАНЗАКЦИИ С АВТОМАТИЧЕСКИМ ПОДБОРОМ ISO
        logger.info(f"Симуляция транзакции минтинга для ISO: {final_iso}...")
        sim_success, sim_error = simulate_mint_transaction(
            contract=contract,
            address=address,
            iso=final_iso,
            fee_wei=fee_wei * MINT_QUANTITY,
            w3=w3
        )
        
        # Если симуляция не прошла и включен автоматический подбор
        if not sim_success and auto_find_iso:
            logger.warning(f"ISO код {final_iso} не прошел симуляцию: {sim_error}")
            logger.info("Запуск автоматического поиска рабочего ISO кода...")
            
            # Ищем рабочий ISO код
            working_iso, attempts = find_working_iso_code(
                contract=contract,
                address=address,
                fee_wei=fee_wei * MINT_QUANTITY,
                w3=w3,
                max_attempts=20
            )
            
            iso_attempts = attempts
            
            if working_iso is None:
                raise RuntimeError(
                    f"Не удалось найти рабочий ISO код за {attempts} попыток. "
                    f"Последняя ошибка: {sim_error}"
                )
            
            final_iso = working_iso
            logger.success(f"Используем найденный рабочий ISO код: {final_iso}")
        elif not sim_success:
            # Если симуляция не прошла и автоматический подбор отключен
            raise RuntimeError(f"Симуляция транзакции не прошла: {sim_error}")
        else:
            logger.success("Симуляция транзакции прошла успешно")
        
        # 7. Оценка gas (дополнительная проверка)
        try:
            gas_estimate = contract.functions.mint(MINT_QUANTITY, final_iso).estimate_gas({
                'from': address,
                'value': fee_wei * MINT_QUANTITY
            })
            logger.info(f"Оценка gas: {gas_estimate}")
        except Exception as e:
            logger.warning(f"Ошибка оценки gas: {e}, используем фиксированное значение")
            gas_estimate = 200000  # Fallback значение
        
        # 8. Построение транзакции
        nonce = w3.eth.get_transaction_count(address)
        gas_price = w3.eth.gas_price
        
        transaction = contract.functions.mint(MINT_QUANTITY, final_iso).build_transaction({
            'from': address,
            'value': fee_wei * MINT_QUANTITY,
            'gas': int(gas_estimate * 1.2),  # +20% запас
            'gasPrice': gas_price,
            'nonce': nonce,
            'chainId': CHAIN_ID
        })
        
        # 9. Подписание транзакции
        signed_txn = account.sign_transaction(transaction)
        
        # 10. Отправка транзакции
        logger.info("Отправка транзакции...")
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        logger.info(f"Транзакция отправлена: {tx_hash.hex()}")
        
        # 11. Ожидание подтверждения
        logger.info("Ожидание подтверждения транзакции...")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        
        if receipt.status == 1:
            logger.success(f"Транзакция подтверждена: {tx_hash.hex()}")
            return {
                'success': True,
                'tx_hash': tx_hash.hex(),
                'error': None,
                'iso_used': final_iso,
                'iso_attempts': iso_attempts
            }
        else:
            raise RuntimeError(f"Транзакция не прошла (status=0): {tx_hash.hex()}")
            
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Ошибка при минтинге NFT: {error_msg}")
        return {
            'success': False,
            'tx_hash': None,
            'error': error_msg,
            'iso_used': final_iso or "unknown",
            'iso_attempts': iso_attempts
        }


def run() -> None:
    """
    Главная функция для запуска модуля из main.py.
    Загружает все ключи и выполняет минтинг NFT для каждого кошелька.
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
        logger.info("База данных инициализирована")
        
        # 2. Подключение к RPC и загрузка контракта
        w3 = Web3(Web3.HTTPProvider(RPC_URL_DEFAULT, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise RuntimeError("RPC недоступен")
        
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(METAMAP_CONTRACT_ADDRESS),
            abi=METAMAP_ABI
        )
        logger.info("Контракт загружен")
        
        # 3. Запрос задержки у пользователя
        logger.info("=" * 60)
        logger.info("НАСТРОЙКА ЗАДЕРЖКИ МЕЖДУ КОШЕЛЬКАМИ")
        logger.info("=" * 60)
        
        try:
            delay_minutes = get_delay_minutes_from_user()
            delay_seconds = delay_minutes * 60
            logger.info(f"Установлена задержка: {delay_minutes} минут ({delay_seconds} секунд) между кошельками")
        except (KeyboardInterrupt, EOFError):
            # Если пользователь прервал ввод - используем значение по умолчанию
            delay_minutes = DEFAULT_DELAY_MINUTES
            delay_seconds = delay_minutes * 60
            logger.info(f"Используется значение по умолчанию: {delay_minutes} минут ({delay_seconds} секунд)")
        except Exception as e:
            # При любой ошибке - используем значение по умолчанию
            delay_minutes = DEFAULT_DELAY_MINUTES
            delay_seconds = delay_minutes * 60
            logger.warning(f"Ошибка при вводе параметров: {e}, используется значение по умолчанию: {delay_minutes} минут")
        
        # 4. Проверка fee контракта (критическая проверка)
        if not check_fee_safety(contract):
            logger.error("Остановка выполнения для безопасности")
            raise SystemExit(1)
        
        current_fee = get_contract_fee(contract)
        logger.info(f"Fee контракта: {format_eth(current_fee)} ETH (максимум: {format_eth(MAX_FEE)} ETH)")
        
        # 5. Загрузка всех ключей
        all_keys = load_all_keys()
        logger.info(f"Загружено ключей: {len(all_keys)}")
        
        # 6. Основной цикл
        wallets_completed = 0
        wallets_skipped = 0
        wallets_failed = 0
        
        # Перемешиваем ключи случайно
        indices = list(range(len(all_keys)))
        random.shuffle(indices)
        
        for i, key_index in enumerate(indices):
            key_num = i + 1
            logger.info(f"=" * 60)
            logger.info(f"Обработка ключа {key_num}/{len(all_keys)} (индекс: {key_index})")
            logger.info(f"=" * 60)
            
            try:
                # Загружаем приватный ключ
                private_key = load_private_key(key_index=key_index)
                wallet_address = Web3.to_checksum_address(
                    Web3().eth.account.from_key(private_key).address
                )
                logger.info(f"Адрес кошелька: {wallet_address}")
                
                # Проверка БД
                if is_wallet_completed(wallet_address, "metamap", QUESTS_DB_PATH):
                    logger.info(f"[SKIP DB] {wallet_address} уже выполнен")
                    wallets_skipped += 1
                    continue  # Переход к следующему кошельку БЕЗ задержки
                
                # Проверка баланса NFT
                nft_balance = check_nft_balance(wallet_address, contract)
                if nft_balance > 0:
                    logger.info(f"[SKIP] {wallet_address} уже имеет {nft_balance} NFT")
                    wallets_skipped += 1
                    continue  # Переход к следующему кошельку БЕЗ задержки
                
                # Повторная проверка fee перед минтингом (на случай изменения)
                if not check_fee_safety(contract):
                    logger.error("Fee превысила максимум во время выполнения, остановка")
                    raise SystemExit(1)
                
                # Генерация случайного ISO кода (будет автоматически подобран, если не сработает)
                initial_iso = get_random_iso()
                logger.info(f"Начальный ISO код: {initial_iso}")
                
                # Минтинг NFT (с автоматическим подбором ISO при необходимости)
                result = mint_metamap_nft(
                    private_key=private_key,
                    iso=initial_iso,  # Начальный ISO, но будет автоматически подобран, если не сработает
                    auto_find_iso=True  # Включаем автоматический подбор
                )
                
                if result['success']:
                    # Сохранение в БД
                    mark_wallet_completed(
                        wallet_address, "metamap", 1, 1, QUESTS_DB_PATH
                    )
                    iso_info = f"ISO: {result['iso_used']}"
                    if result.get('iso_attempts', 0) > 0:
                        iso_info += f", попыток подбора: {result['iso_attempts']}"
                    logger.success(
                        f"✅ NFT успешно заминтин для {wallet_address} ({iso_info})"
                    )
                    wallets_completed += 1
                else:
                    logger.error(f"❌ Ошибка минтинга: {result.get('error', 'Unknown')}")
                    wallets_failed += 1
                
                # Задержка ТОЛЬКО после реальной обработки кошелька (минтинг или попытка)
                if key_num < len(all_keys):
                    logger.info(f"Ожидание {delay_minutes} минут ({delay_seconds} секунд) перед следующим кошельком...")
                    time.sleep(delay_seconds)
                
            except SystemExit:
                raise
            except Exception as e:
                logger.error(f"Ошибка при обработке ключа {key_num}: {e}")
                wallets_failed += 1
                # Задержка после ошибки (опционально, можно убрать)
                if key_num < len(all_keys):
                    logger.info(f"Ожидание {delay_minutes} минут ({delay_seconds} секунд) перед следующим кошельком...")
                    time.sleep(delay_seconds)
                continue
        
        # Статистика
        logger.info("=" * 60)
        logger.info("СТАТИСТИКА")
        logger.info("=" * 60)
        logger.info(f"Завершено успешно: {wallets_completed}")
        logger.info(f"Пропущено: {wallets_skipped}")
        logger.info(f"Ошибок: {wallets_failed}")
        logger.info(f"Всего обработано: {wallets_completed + wallets_skipped + wallets_failed}")
        
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

