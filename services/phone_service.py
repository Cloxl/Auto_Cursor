import asyncio
import json
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from core.config import Config
from core.logger import logger


@dataclass
class PhoneNumber:
    """手机号信息"""

    phone: str
    country_code: str
    deformated_number: str


class YeziApiClient:
    """椰子API客户端"""

    def __init__(self, config: Config):
        self.config = config.phone_service_config.yezi
        self.session: Optional[aiohttp.ClientSession] = None
        self.token: Optional[str] = None  # API token

    async def _get_session(self) -> aiohttp.ClientSession:
        """获取或创建 aiohttp session"""
        if self.session is None or self.session.closed:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            }
            self.session = aiohttp.ClientSession(headers=headers)
        return self.session

    async def close(self):
        """关闭 session"""
        if self.session and not self.session.closed:
            await self.session.close()

    async def _login(self) -> bool:
        """登录获取token"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                session = await self._get_session()
                url = f"{self.config.api_url}{self.config.login_endpoint}"
                headers = {
                    "Accept": "application/json",
                }
                params = {
                    "username": self.config.username,
                    "password": self.config.password,
                }

                async with session.get(url, headers=headers, params=params) as response:
                    if response.status != 200:
                        logger.error(
                            f"登录请求失败(尝试{attempt + 1}/{max_retries}): HTTP {response.status}"
                        )
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)
                            continue
                        return False

                    data = await response.text()

                    # 检查是否为空响应
                    if not data.strip():
                        logger.error(
                            f"椰子API返回空响应(尝试{attempt + 1}/{max_retries})"
                        )
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)
                            continue
                        return False

                    try:
                        result = json.loads(data)
                    except json.JSONDecodeError:
                        logger.error(
                            f"椰子API返回非JSON格式(尝试{attempt + 1}/{max_retries}): {data[:100]}..."
                        )
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)
                            continue
                        return False

                    # 根据椰子API文档解析登录响应
                    if "token" in result:
                        self.token = result["token"]
                        if "data" in result and result["data"]:
                            balance = result["data"][0].get("money", "未知")
                            user_id = result["data"][0].get("id", "未知")
                            logger.info(
                                f"椰子API登录成功 - 用户ID: {user_id}, 余额: {balance}"
                            )
                        else:
                            logger.info("椰子API登录成功")
                        return True
                    else:
                        logger.error(
                            f"椰子API登录失败(尝试{attempt + 1}/{max_retries}): {result}"
                        )
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)
                            continue
                        return False

            except Exception as e:
                logger.error(
                    f"椰子API登录异常(尝试{attempt + 1}/{max_retries}): {str(e)}"
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
                    continue
                return False

        return False

    async def _ensure_token(self) -> bool:
        """确保有有效的token"""
        if not self.token:
            return await self._login()
        return True

    async def get_phone_number(self) -> Optional[PhoneNumber]:
        """获取手机号"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if not await self._ensure_token():
                    logger.error("获取token失败，无法继续获取手机号")
                    return None

                session = await self._get_session()
                url = f"{self.config.api_url}{self.config.get_phone_endpoint}"
                headers = {
                    "Accept": "application/json",
                }
                params = {
                    "token": self.token,
                    "project_id": self.config.project_id,
                }

                async with session.get(url, headers=headers, params=params) as response:
                    if response.status != 200:
                        logger.error(
                            f"获取手机号请求失败(尝试{attempt + 1}/{max_retries}): HTTP {response.status}"
                        )
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)
                            continue
                        return None

                    data = await response.text()

                    # 检查是否为空响应
                    if not data.strip():
                        logger.error(
                            f"椰子API返回空响应(尝试{attempt + 1}/{max_retries})"
                        )
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)
                            continue
                        return None

                    try:
                        result = json.loads(data)
                    except json.JSONDecodeError:
                        logger.error(
                            f"椰子API返回非JSON格式(尝试{attempt + 1}/{max_retries}): {data[:100]}..."
                        )
                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)
                            continue
                        return None

                    if result.get("message") == "ok" and "mobile" in result:
                        phone = result["mobile"]
                        remaining_count = result.get("1分钟内剩余取卡数", "N/A")

                        # 检查剩余取卡数，小于10时停止请求
                        try:
                            if remaining_count != "N/A" and int(remaining_count) < 10:
                                logger.warning(
                                    f"剩余取卡数不足 ({remaining_count})，停止请求以避免IP被拉黑"
                                )
                                return None
                        except (ValueError, TypeError):
                            pass

                        # 格式化手机号
                        deformated_number = f"({phone[:3]}){phone[3:7]}-{phone[7:]}"

                        logger.info(
                            f"获取手机号成功: {phone}, 剩余次数: {remaining_count}"
                        )

                        return PhoneNumber(
                            phone=phone,
                            country_code=self.config.country_code,
                            deformated_number=deformated_number,
                        )
                    else:
                        # 检查是否是API错误信息
                        if "message" in result and result["message"] != "ok":
                            logger.error(
                                f"椰子API错误(尝试{attempt + 1}/{max_retries}): {result['message']}"
                            )
                        else:
                            logger.error(
                                f"椰子API返回格式错误(尝试{attempt + 1}/{max_retries}): {result}"
                            )

                        if attempt < max_retries - 1:
                            await asyncio.sleep(2)
                            continue
                        return None

            except Exception as e:
                logger.error(
                    f"获取手机号异常(尝试{attempt + 1}/{max_retries}): {str(e)}"
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
                    continue
                return None

        return None

    async def get_verification_code(self, phone: str) -> Optional[str]:
        """获取验证码"""
        try:
            if not await self._ensure_token():
                logger.error("获取token失败，无法继续获取验证码")
                return None

            session = await self._get_session()
            url = f"{self.config.api_url}{self.config.get_sms_endpoint}"
            headers = {
                "Accept": "application/json",
            }
            params = {
                "token": self.token,
                "project_id": self.config.project_id,
                "phone_num": phone,
            }

            # 轮询获取验证码
            for attempt in range(20):  # 最多等待20次，约40秒
                try:
                    async with session.get(
                        url, headers=headers, params=params
                    ) as response:
                        if response.status != 200:
                            logger.error(
                                f"获取验证码请求失败(第{attempt + 1}次): HTTP {response.status}"
                            )
                            await asyncio.sleep(2)
                            continue

                        data = await response.text()

                        # 检查是否为空响应
                        if not data.strip():
                            logger.debug(f"第{attempt + 1}次查询，API返回空响应")
                            await asyncio.sleep(2)
                            continue

                        try:
                            result = json.loads(data)
                        except json.JSONDecodeError:
                            logger.error(
                                f"验证码API返回非JSON格式(第{attempt + 1}次): {data[:100]}..."
                            )
                            await asyncio.sleep(2)
                            continue

                        # 根据椰子API文档解析响应
                        if result.get("message") == "ok":
                            # 有短信的情况：{"message": "ok", "code": "807272", "data": [...]}
                            if "code" in result:
                                code = result["code"]
                                logger.info(f"成功获取验证码: {code}")
                                return code
                            # 无短信的情况：{"message": "ok", "data": []}
                            elif result.get("data") == []:
                                logger.debug(f"第{attempt + 1}次查询，暂无验证码")
                                await asyncio.sleep(2)
                                continue
                            else:
                                logger.debug(
                                    f"第{attempt + 1}次查询，暂无验证码 (data: {result.get('data')})"
                                )
                                await asyncio.sleep(2)
                                continue
                        elif result.get("message") == "短信还未到达,请继续获取":
                            # 椰子API特有的响应格式
                            logger.debug(f"第{attempt + 1}次查询，短信还未到达")
                            await asyncio.sleep(2)
                            continue
                        else:
                            # 其他错误情况
                            if "message" in result:
                                logger.error(
                                    f"验证码API错误(第{attempt + 1}次): {result['message']}"
                                )
                            else:
                                logger.warning(
                                    f"未知响应格式(第{attempt + 1}次): {result}"
                                )
                            await asyncio.sleep(2)
                            continue

                except Exception as e:
                    logger.error(f"获取验证码异常(第{attempt + 1}次): {str(e)}")
                    await asyncio.sleep(2)
                    continue

            logger.error("获取验证码超时")
            return None

        except Exception as e:
            logger.error(f"获取验证码过程异常: {str(e)}")
            return None

    async def free_phone_number(self, phone: str):
        """释放手机号"""
        try:
            if not await self._ensure_token():
                return

            session = await self._get_session()
            url = f"{self.config.api_url}{self.config.free_phone_endpoint}"
            headers = {
                "Accept": "application/json",
            }
            params = {"token": self.token, "phone_num": phone}

            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.text()
                    result = json.loads(data)

                    if result.get("message") == "ok":
                        logger.info(f"成功释放手机号: {phone}")
                    else:
                        logger.warning(f"释放手机号响应: {result}")
                else:
                    logger.error(f"释放手机号失败: HTTP {response.status}")

        except Exception as e:
            logger.error(f"释放手机号异常: {str(e)}")

    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.close()


class PhoneVerificationService:
    """手机验证服务"""

    def __init__(self, config: Config, fetch_manager):
        self.config = config
        self.fetch_manager = fetch_manager

        if config.phone_service_config.provider == "yezi":
            self.api_client = YeziApiClient(config)
        else:
            raise ValueError(
                f"不支持的手机服务提供商: {config.phone_service_config.provider}"
            )

    async def handle_phone_verification(self, redirect_url, wuid, proxy):
        q = urlparse(redirect_url)
        user_id = q.query.split("user_id=")[1].split("&")[0]
        pending_authentication_token = q.query.split("pending_authentication_token=")[
            1
        ].split("&")[0]

        # 获取手机号，添加空值检查
        pm = await self.api_client.get_phone_number()
        if pm is None:
            logger.error("获取手机号失败")
            return False

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
            "Accept": "text/x-component",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "pragma": "no-cache",
            "cache-control": "no-cache",
            "sec-ch-ua-platform": '"Windows"',
            "next-action": "8e7a636b3b401634f6a5edf8d0dc7257716997ab",
            "sec-ch-ua": '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "next-router-state-tree": f"%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22(fixed-layout)%22%2C%7B%22children%22%3A%5B%22radar-challenge%22%2C%7B%22children%22%3A%5B%22send%22%2C%7B%22children%22%3A%5B%22__PAGE__%3F%7B%5C%22pending_authentication_token%5C%22%3A%5C%22{pending_authentication_token}%5C%22%2C%5C%22user_id%5C%22%3A%5C%22{user_id}%5C%22%2C%5C%22state%5C%22%3A%5C%22%7B%5C%5C%5C%22returnTo%5C%5C%5C%22%3A%5C%5C%5C%22%2Fsettings%5C%5C%5C%22%7D%5C%22%2C%5C%22redirect_uri%5C%22%3A%5C%22https%3A%2F%2Fcursor.com%2Fapi%2Fauth%2Fcallback%5C%22%7D%22%2C%7B%7D%2C%22%2Fradar-challenge%2Fsend%3Fpending_authentication_token%3D{pending_authentication_token}%26user_id%3D{user_id}%26state%3D%257B%2522returnTo%2522%253A%2522%252Fsettings%2522%257D%26redirect_uri%3Dhttps%253A%252F%252Fcursor.com%252Fapi%252Fauth%252Fcallback%22%2C%22refresh%22%5D%7D%5D%7D%5D%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
            "origin": "https://authenticator.cursor.sh",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": f"https://authenticator.cursor.sh/radar-challenge/send?pending_authentication_token={pending_authentication_token}&user_id={user_id}&state=%7B%22returnTo%22%3A%22%2Fsettings%22%7D&redirect_uri=https%3A%2F%2Fcursor.com%2Fapi%2Fauth%2Fcallback",
            "accept-language": "zh-CN,zh;q=0.9",
            "priority": "u=1, i",
        }

        cookies = {
            "__wuid": wuid,
            "__cf_bm": "ukUhZSq0mH1968GhA4uDTp_wkApMNr7WC0tcod_1w9Q-1749637572-1.0.1.1-ll.mFpHZuVKNL6L7mGKQZCHZhkK8rtMsXrAY3zBHbA61G1Lni2KmpQ88lKOTGeUthPy1gi7tMyaDMTZSvNSshMOqHeAakHtPRLnUzx9uVMA",
            "_cfuvid": "u_xbD8Hgz5593h_mR1_c0mgY0e.4vKyCMhEEcL8066Y-1749637572787-0.0.1.1-604800000",
            "_dd_s": "rum=0&expire=1749638479315",
        }

        url = "https://authenticator.cursor.sh/radar-challenge/send"
        params = {
            "pending_authentication_token": pending_authentication_token,
            "user_id": user_id,
            "state": '{"returnTo":"/settings"}',
            "redirect_uri": "https://cursor.com/api/auth/callback",
        }

        # 修复数据格式 - 使用独立的表单字段而不是拼接字符串
        data = {
            "1_country_code": f"+{pm.country_code}",
            "1_local_number": pm.deformated_number,
            "1_phone_number": f"+{pm.country_code}{pm.phone}",
            "1_redirect_uri": "https://cursor.com/api/auth/callback",
            "1_state": '{"returnTo":"/settings"}',
            "1_user_id": user_id,
            "1_pending_authentication_token": pending_authentication_token,
            "0": '["$K1"]',
        }

        try:
            logger.info(f"发送手机验证请求 - 手机号: {pm.phone}")

            # 添加详细的请求调试信息
            # logger.debug("请求方法: POST")
            # logger.debug(f"请求URL: {url}")
            # logger.debug(f"请求参数: {params}")
            # logger.debug(f"请求数据: {data}")
            # logger.debug(f"请求头: {headers}")
            # logger.debug(f"Cookies: {cookies}")

            response = await self.fetch_manager.request(
                "POST",
                url,
                headers=headers,
                cookies=cookies,
                params=params,
                data=data,
                proxy=proxy,
            )

            # 调试响应信息
            # logger.debug(f"响应状态码: {response.get('status', 'unknown')}")
            # logger.debug(f"响应头: {response.get('headers', {})}")

            # 检查原始响应内容
            raw_body = response["body"]
            # logger.debug(f"原始响应内容类型: {type(raw_body)}")
            # logger.debug(f"原始响应内容长度: {len(raw_body)} bytes")
            # logger.debug(f"原始响应内容前100字节: {raw_body[:100]}")

            # 尝试不同的解码方式
            response_text = ""
            try:
                response_text = raw_body.decode("utf-8")
                # logger.debug(f"UTF-8解码成功，长度: {len(response_text)}")
            except UnicodeDecodeError as e:
                logger.error(f"UTF-8解码失败: {e}")
                try:
                    response_text = raw_body.decode("latin-1")
                    logger.debug(f"Latin-1解码成功，长度: {len(response_text)}")
                except Exception as e2:
                    logger.error(f"Latin-1解码也失败: {e2}")
                    response_text = str(raw_body)

            # logger.debug(f"解码后的响应内容: {response_text}")

            if "verification_id" not in response_text:
                logger.debug(response_text)
                logger.error("发送手机验证请求失败，未找到 verification_id")
                # logger.debug(f"响应内容: {response_text[:500]}...")
                return False

            match = re.search(r'"verification_id":"([^"]+)"', response_text)
            if not match:
                logger.error("无法从响应中提取 verification_id")
                return False

            verification_id = match.group(1)
            logger.info(f"提取到的 verification_id: {verification_id}")

            # 修复：使用异步调用获取验证码
            code = await self.api_client.get_verification_code(phone=pm.phone)
            if not code:
                logger.error("获取验证码失败")
                await self.api_client.free_phone_number(pm.phone)
                return False

            logger.info(f"获取到验证码: {code}")

            verify_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "text/x-component",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "pragma": "no-cache",
                "cache-control": "no-cache",
                "sec-ch-ua-platform": '"Windows"',
                "next-action": "5cded633b2181dd83758af9fe6a13b9e2b16ff50",
                "sec-ch-ua": '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "next-router-state-tree": f"%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22(fixed-layout)%22%2C%7B%22children%22%3A%5B%22radar-challenge%22%2C%7B%22children%22%3A%5B%22verify%22%2C%7B%22children%22%3A%5B%22__PAGE__%3F%7B%5C%22redirect_uri%5C%22%3A%5C%22https%3A%2F%2Fcursor.com%2Fapi%2Fauth%2Fcallback%5C%22%2C%5C%22state%5C%22%3A%5C%22%7B%5C%5C%5C%22returnTo%5C%5C%5C%22%3A%5C%5C%5C%22%2Fsettings%5C%5C%5C%22%7D%5C%22%2C%5C%22country_code%5C%22%3A%5C%22%2B{pm.country_code}%5C%22%2C%5C%22local_number%5C%22%3A%5C%22{pm.deformated_number}%5C%22%2C%5C%22phone_number%5C%22%3A%5C%22%2B{pm.country_code}{pm.phone}%5C%22%2C%5C%22user_id%5C%22%3A%5C%22{user_id}%5C%22%2C%5C%22pending_authentication_token%5C%22%3A%5C%22{pending_authentication_token}%5C%22%7D%22%2C%7B%7D%2C%22%2Fradar-challenge%2Fverify%3Fredirect_uri%3Dhttps%253A%252F%252Fcursor.com%252Fapi%252Fauth%252Fcallback%26state%3D%257B%2522returnTo%2522%253A%2522%252Fsettings%2522%257D%26country_code%3D%252B{pm.country_code}%26local_number%3D{pm.deformated_number}%26phone_number%3D%252B{pm.country_code}{pm.phone}%26user_id%3D{user_id}%26pending_authentication_token%3D{pending_authentication_token}%22%2C%22refresh%22%5D%7D%5D%7D%5D%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
                "origin": "https://authenticator.cursor.sh",
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                "referer": f"https://authenticator.cursor.sh/radar-challenge/verify?redirect_uri=https%3A%2F%2Fcursor.com%2Fapi%2Fauth%2Fcallback&state=%7B%22returnTo%22%3A%22%2Fsettings%22%7D&country_code=%2B{pm.country_code}&local_number={pm.deformated_number}&phone_number=%2B{pm.country_code}{pm.phone}&user_id={user_id}&pending_authentication_token={pending_authentication_token}",
                "accept-language": "zh-CN,zh;q=0.9",
                "priority": "u=1, i",
            }

            verify_url = "https://authenticator.cursor.sh/radar-challenge/verify"
            verify_params = {
                "redirect_uri": "https://cursor.com/api/auth/callback",
                "state": '{"returnTo":"/settings"}',
                "country_code": f"+{pm.country_code}",
                "local_number": f"{pm.deformated_number}",
                "phone_number": f"+{pm.country_code}{pm.phone}",
                "user_id": user_id,
                "pending_authentication_token": pending_authentication_token,
            }

            # 修复验证请求的数据格式
            verify_data = {
                "1_code": code,
                "1_redirect_uri": "https://cursor.com/api/auth/callback",
                "1_state": '{"returnTo":"/settings"}',
                "1_pending_authentication_token": pending_authentication_token,
                "1_verification_id": verification_id,
                "1_phone_number": f"+{pm.country_code}{pm.phone}",
                "0": '["$K1"]',
            }

            logger.info("发送验证码验证请求")
            verify_response = await self.fetch_manager.request(
                "POST",
                verify_url,
                headers=verify_headers,
                cookies=cookies,
                params=verify_params,
                data=verify_data,
                proxy=proxy,
                impersonate="chrome131",
            )

            if "error" in verify_response:
                logger.error(f"验证码验证请求失败: {verify_response['error']}")
                await self.api_client.free_phone_number(pm.phone)
                return False

            logger.info(f"验证响应状态: {verify_response['status']}")
            # logger.debug(f"验证响应头: {verify_response['headers']}")

            # 释放手机号
            await self.api_client.free_phone_number(pm.phone)

            # 检查是否有重定向头
            redirect_url = verify_response["headers"].get("x-action-redirect")
            if redirect_url:
                logger.info(f"验证成功，获得重定向URL: {redirect_url}")
                return redirect_url
            else:
                logger.warning("验证请求完成，但未获得重定向URL")
                # 手动解码验证响应内容
                verify_response_text = verify_response["body"].decode("utf-8")
                logger.debug(f"验证响应内容: {verify_response_text[:500]}...")
                return False

        except Exception as e:
            logger.error(f"手机验证过程中发生异常: {str(e)}")
            # 确保释放手机号
            await self.api_client.free_phone_number(pm.phone)
            return False

    async def close(self):
        """关闭服务"""
        if hasattr(self.api_client, "close"):
            await self.api_client.close()

    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.close()
