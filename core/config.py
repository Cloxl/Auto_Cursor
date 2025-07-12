from dataclasses import dataclass, field
from typing import List, Tuple

import yaml


@dataclass
class GlobalConfig:
    max_concurrency: int
    timeout: int
    retry_times: int


@dataclass
class DatabaseConfig:
    path: str
    pool_size: int


@dataclass
class ProxyConfig:
    api_url: str
    batch_size: int
    check_interval: int
    use_local_proxy: bool = False


@dataclass
class RegisterConfig:
    delay_range: Tuple[int, int]
    batch_size: int
    max_accounts: int = 0
    batch_interval: int = 30
    timeout: int = 90
    use_fake_domain: bool = True


@dataclass
class EmailConfig:
    file_path: str = "email.txt"
    provider: str = "file"  # 可能的值: "file", "local"
    # 本地API配置
    local_url: str = ""
    local_auth: str = ""


@dataclass
class CapsolverConfig:
    api_key: str
    website_url: str
    website_key: str


@dataclass
class YesCaptchaConfig:
    client_key: str
    website_url: str
    website_key: str
    use_cn_server: bool


@dataclass
class CustomTokenConfig:
    api_url: str = ""
    limit_param: str = "limit"
    status_param: str = "status"
    status_value: str = "0"
    token_key: str = "tokens"
    headers: dict = field(default_factory=dict)


@dataclass
class CaptchaConfig:
    provider: str
    capsolver: CapsolverConfig
    yescaptcha: YesCaptchaConfig
    custom: CustomTokenConfig = field(default_factory=CustomTokenConfig)


@dataclass
class QQImapConfig:
    enabled: bool = False
    qq_email: str = ""
    qq_password: str = ""  # QQ邮箱授权码
    domains: List[str] = field(default_factory=lambda: ["mail.cloxl.com"])
    domain_quota: int = 0  # 每个域名最大注册数量，0表示不限制
    imap_server: str = "imap.qq.com"
    imap_port: int = 993


@dataclass
class YeziApiConfig:
    api_url: str = "http://api.sqhyw.net:90"
    backup_url: str = "http://api.xuce.top:90"
    username: str = ""
    password: str = ""
    project_id: str = ""
    country_code: str = "86"
    timeout: int = 60
    max_retries: int = 3
    login_endpoint: str = "/api/logins"
    get_phone_endpoint: str = "/api/get_mobile"
    get_sms_endpoint: str = "/api/get_message"
    free_phone_endpoint: str = "/api/free_mobile"


@dataclass
class PhoneServiceConfig:
    enabled: bool = False
    provider: str = "yezi"  # 目前只支持椰子API
    yezi: YeziApiConfig = field(default_factory=YeziApiConfig)


@dataclass
class Config:
    global_config: GlobalConfig
    database_config: DatabaseConfig
    proxy_config: ProxyConfig
    register_config: RegisterConfig
    email_config: EmailConfig
    captcha_config: CaptchaConfig
    qq_imap_config: QQImapConfig = field(default_factory=QQImapConfig)
    phone_service_config: PhoneServiceConfig = field(default_factory=PhoneServiceConfig)

    @classmethod
    def from_yaml(cls, path: str = "config.yaml"):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # 创建 captcha 配置对象
        captcha_data = data["captcha"]
        captcha_config = CaptchaConfig(
            provider=captcha_data["provider"],
            capsolver=CapsolverConfig(**captcha_data["capsolver"]),
            yescaptcha=YesCaptchaConfig(**captcha_data["yescaptcha"]),
            custom=CustomTokenConfig(
                **(captcha_data.get("custom", captcha_data.get("custom_token", {})))
            ),
        )

        # 创建 email 配置对象
        email_data = data.get("email", {})
        email_config = EmailConfig(
            file_path=email_data.get("file_path", "email.txt"),
            provider=email_data.get("provider", "file"),
            local_url=email_data.get("local_url", ""),
            local_auth=email_data.get("local_auth", ""),
        )

        if "qq_imap" in data:
            qq_imap_config = QQImapConfig(
                enabled=data["qq_imap"].get("enabled", False),
                qq_email=data["qq_imap"].get("qq_email", ""),
                qq_password=data["qq_imap"].get("qq_password", ""),
                domains=data["qq_imap"].get("domains", ["mail.cloxl.com"]),
                domain_quota=data["qq_imap"].get("domain_quota", 0),
                imap_server=data["qq_imap"].get("imap_server", "imap.qq.com"),
                imap_port=data["qq_imap"].get("imap_port", 993),
            )
        else:
            qq_imap_config = QQImapConfig()

        # 创建手机服务配置
        phone_service_config = PhoneServiceConfig()
        if "phone_service" in data:
            phone_data = data["phone_service"]
            yezi_config = YeziApiConfig()
            if "yezi" in phone_data:
                yezi_data = phone_data["yezi"]
                yezi_config = YeziApiConfig(
                    api_url=yezi_data.get("api_url", "http://api.sqhyw.net:90"),
                    backup_url=yezi_data.get("backup_url", "http://api.xuce.top:90"),
                    username=yezi_data.get("username", ""),
                    password=yezi_data.get("password", ""),
                    project_id=yezi_data.get("project_id", ""),
                    country_code=yezi_data.get("country_code", "86"),
                    timeout=yezi_data.get("timeout", 60),
                    max_retries=yezi_data.get("max_retries", 3),
                    login_endpoint=yezi_data.get("login_endpoint", "/api/logins"),
                    get_phone_endpoint=yezi_data.get(
                        "get_phone_endpoint", "/api/get_mobile"
                    ),
                    get_sms_endpoint=yezi_data.get(
                        "get_sms_endpoint", "/api/get_message"
                    ),
                    free_phone_endpoint=yezi_data.get(
                        "free_phone_endpoint", "/api/free_mobile"
                    ),
                )

            phone_service_config = PhoneServiceConfig(
                enabled=phone_data.get("enabled", False),
                provider=phone_data.get("provider", "yezi"),
                yezi=yezi_config,
            )

        config = cls(
            global_config=GlobalConfig(**data["global"]),
            database_config=DatabaseConfig(**data["database"]),
            proxy_config=ProxyConfig(**data["proxy"]),
            register_config=RegisterConfig(**data["register"]),
            email_config=email_config,
            captcha_config=captcha_config,
            qq_imap_config=qq_imap_config,
            phone_service_config=phone_service_config,
        )

        return config
