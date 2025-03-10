from secrets import token_hex


class Settings:
    # TODO MAKE IT IN .ENV and Pydantic
    API_V1_STR: str = "/api/v1"
    # in prod use token_hex
    SECRET_KEY: str = token_hex(32)
    CSRF_SECRET_KEY: str = token_hex(32)
    JWT_TIME_LIVE: int = 10800
    DBURL: str = "sqlite:///sqlite.db"
    # DBURL: str = "sqlite:////home/samuraj/Documents/code/Web-messenger/sqlite.db"
    # turn of in production
    DEBUG: bool = True
    PROJECT_NAME: str = "Web Messenger"
    PROJECT_VERSION: str = "1.0.0"


settings = Settings()
