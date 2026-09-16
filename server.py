# Алиас-точка входа на случай, если хостинг ищет server.py как веб-сервер.
from bot import app, main

if __name__ == "__main__":
    main()
