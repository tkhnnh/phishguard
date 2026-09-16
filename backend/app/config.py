from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()