#!/usr/bin/env python3
from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from loguru import logger

# Позволяет запускать файл напрямую: `python modules/db_utils.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    root_s = str(PROJECT_ROOT)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)

# Путь к БД квестов
QUESTS_DB_PATH = PROJECT_ROOT / "quests.db"


def init_quests_database(db_path: Path = QUESTS_DB_PATH) -> None:
    """
    Создает базу данных и таблицы для хранения выполненных кошельков по квестам.

    Args:
        db_path: Путь к файлу базы данных
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Создаем таблицу completed_wallets
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS completed_wallets (
                address TEXT NOT NULL,
                module TEXT NOT NULL,
                completed_count INTEGER NOT NULL,
                target_count INTEGER NOT NULL,
                completed_at TIMESTAMP NOT NULL,
                last_check TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (address, module)
            )
            """
        )

        # Создаем индексы
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_completed_wallets_module 
            ON completed_wallets(module)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_completed_wallets_completed_at 
            ON completed_wallets(completed_at)
            """
        )

        conn.commit()
        conn.close()
        logger.debug(f"База данных квестов инициализирована: {db_path}")

    except Exception as e:
        logger.error(f"Ошибка при инициализации базы данных квестов: {e}")
        raise


def is_wallet_completed(
    address: str, module: str, db_path: Path = QUESTS_DB_PATH
) -> bool:
    """
    Проверяет, выполнен ли квест для указанного кошелька и модуля.

    Args:
        address: Адрес кошелька (checksum format)
        module: Название модуля ('redbutton', 'cashorcrash', 'uniswap')
        db_path: Путь к файлу базы данных

    Returns:
        True если кошелек уже выполнен, False если нет
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT address, module, completed_count, target_count
            FROM completed_wallets
            WHERE address = ? AND module = ?
            """,
            (address, module),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            logger.debug(
                f"Кошелек {address} для модуля {module} найден в БД: {row[2]}/{row[3]}"
            )
            return True

        return False

    except Exception as e:
        logger.warning(f"Ошибка при проверке БД для {address} ({module}): {e}")
        # При ошибке БД возвращаем False, чтобы продолжить проверку через API
        return False


def get_wallet_progress(
    address: str, module: str, db_path: Path = QUESTS_DB_PATH
) -> Optional[dict]:
    """
    Получает информацию о прогрессе кошелька из БД.

    Args:
        address: Адрес кошелька (checksum format)
        module: Название модуля ('redbutton', 'cashorcrash', 'uniswap')
        db_path: Путь к файлу базы данных

    Returns:
        Словарь с данными о прогрессе или None если не найден
    """
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT address, module, completed_count, target_count, 
                   completed_at, last_check, created_at
            FROM completed_wallets
            WHERE address = ? AND module = ?
            """,
            (address, module),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "address": row["address"],
                "module": row["module"],
                "completed_count": row["completed_count"],
                "target_count": row["target_count"],
                "completed_at": (
                    datetime.fromisoformat(row["completed_at"])
                    if row["completed_at"]
                    else None
                ),
                "last_check": (
                    datetime.fromisoformat(row["last_check"])
                    if row["last_check"]
                    else None
                ),
                "created_at": (
                    datetime.fromisoformat(row["created_at"])
                    if row["created_at"]
                    else None
                ),
            }

        return None

    except Exception as e:
        logger.warning(f"Ошибка при получении прогресса из БД для {address} ({module}): {e}")
        return None


def mark_wallet_completed(
    address: str,
    module: str,
    completed_count: int,
    target_count: int,
    db_path: Path = QUESTS_DB_PATH,
) -> None:
    """
    Сохраняет информацию о выполненном кошельке в БД.

    Args:
        address: Адрес кошелька (checksum format)
        module: Название модуля ('redbutton', 'cashorcrash', 'uniswap')
        completed_count: Выполненное количество транзакций
        target_count: Целевое количество транзакций
        db_path: Путь к файлу базы данных
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        now_utc = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            INSERT OR REPLACE INTO completed_wallets 
            (address, module, completed_count, target_count, completed_at, last_check)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (address, module, completed_count, target_count, now_utc, now_utc),
        )

        conn.commit()
        conn.close()
        logger.debug(
            f"Кошелек {address} для модуля {module} сохранен в БД: {completed_count}/{target_count}"
        )

    except Exception as e:
        logger.error(f"Ошибка при сохранении кошелька в БД: {e}")


def update_wallet_last_check(
    address: str, module: str, db_path: Path = QUESTS_DB_PATH
) -> None:
    """
    Обновляет время последней проверки кошелька.

    Args:
        address: Адрес кошелька (checksum format)
        module: Название модуля ('redbutton', 'cashorcrash', 'uniswap')
        db_path: Путь к файлу базы данных
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        now_utc = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            UPDATE completed_wallets
            SET last_check = ?
            WHERE address = ? AND module = ?
            """,
            (now_utc, address, module),
        )

        conn.commit()
        conn.close()

    except Exception as e:
        logger.debug(f"Ошибка при обновлении last_check для {address} ({module}): {e}")


def get_module_stats(module: str, db_path: Path = QUESTS_DB_PATH) -> dict:
    """
    Получает статистику по модулю из БД.

    Args:
        module: Название модуля ('redbutton', 'cashorcrash', 'uniswap')
        db_path: Путь к файлу базы данных

    Returns:
        Словарь со статистикой
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*) 
            FROM completed_wallets
            WHERE module = ?
            """,
            (module,),
        )

        total = cursor.fetchone()[0]

        conn.close()

        return {
            "module": module,
            "total_completed": total,
        }

    except Exception as e:
        logger.error(f"Ошибка при получении статистики для модуля {module}: {e}")
        return {"module": module, "total_completed": 0}


if __name__ == "__main__":
    # Тестирование функций
    logger.remove()
    logger.add(sys.stderr, level="DEBUG")

    init_quests_database()
    logger.info("База данных инициализирована")

    test_address = "0x1234567890123456789012345678901234567890"
    test_module = "redbutton"

    # Тест проверки несуществующего кошелька
    result = is_wallet_completed(test_address, test_module)
    logger.info(f"is_wallet_completed (не существует): {result}")

    # Тест сохранения
    mark_wallet_completed(test_address, test_module, 15, 15)
    logger.info("Кошелек сохранен в БД")

    # Тест проверки существующего кошелька
    result = is_wallet_completed(test_address, test_module)
    logger.info(f"is_wallet_completed (существует): {result}")

    # Тест получения прогресса
    progress = get_wallet_progress(test_address, test_module)
    logger.info(f"get_wallet_progress: {progress}")

    # Тест статистики
    stats = get_module_stats(test_module)
    logger.info(f"get_module_stats: {stats}")

