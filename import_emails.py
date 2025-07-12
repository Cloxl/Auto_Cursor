import asyncio
import os
from typing import List

import aiosqlite
import requests

from core.config import Config
from core.logger import logger


async def get_accounts_from_local(config: Config) -> List[str]:
    """从本地服务器获取邮箱账号"""
    try:
        # 构建API请求URL
        api_url = config.email_config.local_url
        auth_token = config.email_config.local_auth

        # 准备请求头
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Authorization": auth_token,
            "Connection": "keep-alive",
        }

        logger.info(f"开始从本地服务器获取邮箱账号: {api_url}")

        # 发送请求
        response = requests.post(api_url, headers=headers)

        if response.status_code != 200:
            logger.error(f"本地服务器请求失败，状态码: {response.status_code}")
            return []

        # 解析响应内容
        accounts = response.text.strip().split("\n")
        return accounts

    except Exception as e:
        logger.error(f"从本地服务器获取邮箱账号失败: {str(e)}")
        return []


async def import_emails(config: Config, file_path: str = None):
    """导入邮箱账号到数据库"""
    # 确保数据库目录存在
    db_dir = os.path.dirname(config.database_config.path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
        logger.info(f"创建数据库目录: {db_dir}")

    async with aiosqlite.connect(config.database_config.path) as db:
        # 创建表
        await db.execute("""
            CREATE TABLE IF NOT EXISTS email_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                client_id TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                in_use BOOLEAN DEFAULT 0,
                cursor_password TEXT,
                cursor_cookie TEXT,
                cursor_token TEXT,
                sold BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'pending',
                verification_sent BOOLEAN DEFAULT 0,
                verification_sent_time TIMESTAMP,
                verification_attempts INTEGER DEFAULT 0,
                verification_code TEXT,
                registration_complete BOOLEAN DEFAULT 0,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 根据配置选择导入方式
        provider = config.email_config.provider

        if provider == "local":
            # 从本地服务器获取账号
            logger.info("检测到使用本地服务器，将从服务器获取邮箱账号")
            accounts = await get_accounts_from_local(config)

            # 导入账号到数据库
            count = 0
            for account_line in accounts:
                if account_line.strip():
                    try:
                        # 解析账号信息，格式应与email.txt中的格式一致
                        parts = account_line.strip().split("----")
                        if len(parts) != 4:
                            raise ValueError("数据格式不正确，需要4个字段")

                        email, password, token1, token2 = parts

                        if len(token1) > len(token2):
                            refresh_token, client_id = token1, token2
                        else:
                            refresh_token, client_id = token2, token1

                        await db.execute(
                            """
                            INSERT INTO email_accounts (
                                email, password, client_id, refresh_token, status
                            ) VALUES (?, ?, ?, ?, 'pending')
                            """,
                            (email, password, client_id, refresh_token),
                        )
                        count += 1
                    except aiosqlite.IntegrityError:
                        logger.warning(f"重复的邮箱: {email}")
                    except ValueError as e:
                        logger.error(
                            f"无效的数据行: {account_line.strip()}, 错误: {str(e)}"
                        )

            logger.success(f"成功从本地服务器导入 {count} 个邮箱账号")

        else:
            # 从文件读取账号
            if not file_path:
                file_path = config.email_config.file_path

            logger.info(f"从文件导入邮箱账号: {file_path}")
            # 读取文件并导入数据
            count = 0
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            # 分割行数据
                            parts = line.strip().split("----")
                            if len(parts) != 4:
                                raise ValueError("数据格式不正确，需要4个字段")

                            email, password, token1, token2 = parts

                            if len(token1) > len(token2):
                                refresh_token, client_id = token1, token2
                            else:
                                refresh_token, client_id = token2, token1

                            await db.execute(
                                """
                                INSERT INTO email_accounts (
                                    email, password, client_id, refresh_token, status
                                ) VALUES (?, ?, ?, ?, 'pending')
                            """,
                                (email, password, client_id, refresh_token),
                            )
                            count += 1
                        except aiosqlite.IntegrityError:
                            logger.warning(f"重复的邮箱: {email}")
                        except ValueError as e:
                            logger.error(
                                f"无效的数据行: {line.strip()}, 错误: {str(e)}"
                            )

            logger.success(f"成功从文件导入 {count} 个邮箱账号")

        await db.commit()


if __name__ == "__main__":
    from core.config import Config

    config = Config.from_yaml()
    asyncio.run(import_emails(config))
