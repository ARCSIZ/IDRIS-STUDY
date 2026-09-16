# Точка входа для автоопределения хостинга (приоритет main.py).
# Реэкспортирует ASGI-приложение и функцию запуска из bot.py.
from bot import app, main

if __name__ == "__main__":
    main()
