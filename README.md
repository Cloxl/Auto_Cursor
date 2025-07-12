# Cursor 自动注册工具

批量自动注册 Cursor 账号的异步工具。

## 运行

1. 安装依赖: `pip install -r requirements.txt` 或者 `uv sync`
2. 配置文件: 复制 `config.yaml.example` 为 `config.yaml` 并填写配置
3. 导入邮箱: `python import_emails.py`
4. 开始注册: `python main.py`

## 配置要求

- **代理服务**: 提供可用代理API
- **验证码服务**: Capsolver 或 YesCaptcha API密钥
- **邮箱账号**: Outlook邮箱账号和令牌
- **手机验证**: 椰子API账号(可选)

## 邮箱文件格式

```
email@domain.com----password----client_id----refresh_token
```

## 导出

运行后在 `exports/` 目录生成注册结果的CSV和TXT文件。

## 免责声明

仅供学习研究使用，使用者承担全部风险。

本项目由cursor直接翻译go代码生成，可读性较差，请谨慎使用。