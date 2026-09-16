# Алиас-точка входа на случай, если хостинг ищет app.py как веб-приложение.
from bot import app, main

if __name__ == "__main__":
    main()
