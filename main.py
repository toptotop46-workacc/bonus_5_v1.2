#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Callable, Dict


@dataclass(frozen=True)
class Module:
    key: str
    title: str
    run: Callable[[], None]


def run_redbutton() -> None:
    import asyncio

    from modules.redbutton import run as redbutton_run

    asyncio.run(redbutton_run())


def run_cashorcrash() -> None:
    from modules.CashOrCrash import run as cashorcrash_run

    cashorcrash_run()


def run_uniswap() -> None:
    from modules.uniswap import run as uniswap_run

    uniswap_run()


def run_mint4season() -> None:
    from modules.mint4season import run as mint4season_run

    mint4season_run()


def run_metamap() -> None:
    from modules.metamap import run as metamap_run

    metamap_run()


def build_modules() -> Dict[str, Module]:
    return {
        "1": Module(key="1", title="RedButton", run=run_redbutton),
        "2": Module(key="2", title="CashOrCrash", run=run_cashorcrash),
        "3": Module(key="3", title="Uniswap", run=run_uniswap),
        "4": Module(key="4", title="Mint Season 4", run=run_mint4season),
        "5": Module(key="5", title="MetaMap NFT", run=run_metamap),
    }


def print_menu(modules: Dict[str, Module]) -> None:
    print("\n==============================")
    print("Выбор модуля")
    print("==============================")
    for k in sorted(modules.keys()):
        m = modules[k]
        print(f"{m.key}. {m.title}")
    print("0. Выход")


def main() -> None:
    modules = build_modules()

    parser = argparse.ArgumentParser(
        description="Единая точка входа: меню выбора модулей/запуск модулей по ключу.",
    )
    parser.add_argument(
        "--module",
        "-m",
        dest="module",
        help="Запустить модуль без интерактивного меню.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Показать доступные модули и выйти.",
    )
    args = parser.parse_args()

    key_by_slug: Dict[str, str] = {
        "redbutton": "1",
        "cashorcrash": "2",
        "uniswap": "3",
        "mint4season": "4",
        "metamap": "5",
    }

    if args.list:
        print_menu(modules)
        return

    if args.module:
        choice = key_by_slug.get(args.module.strip().lower())
        if not choice:
            print(f"Неизвестный модуль: {args.module!r}")
            print("Доступные модули: " + ", ".join(sorted(key_by_slug.keys())))
            raise SystemExit(2)

        modules[choice].run()
        return

    # Если окружение неинтерактивное (например, CI), не пытаемся читать input().
    if not sys.stdin.isatty():
        print_menu(modules)
        print("\nПодсказка: для неинтерактивного запуска используйте `--module`.")
        return

    while True:
        print_menu(modules)
        try:
            choice = input("Введите номер: ").strip()
        except EOFError:
            print("\nВвод недоступен (EOF). Используйте `--module` для запуска без меню.")
            return

        if choice in ("0", "q", "quit", "exit"):
            print("Выход.")
            return

        module = modules.get(choice)
        if not module:
            print("Неизвестный пункт меню. Попробуйте ещё раз.")
            continue

        try:
            module.run()
        except KeyboardInterrupt:
            print("\nОтмена пользователем.")
        except Exception as e:
            print(f"Ошибка при выполнении модуля: {e}")


if __name__ == "__main__":
    main()


