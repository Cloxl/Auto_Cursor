import asyncio
import base64
import hashlib
import json
import random
import secrets
import string
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import urllib3
from Crypto.Random import get_random_bytes

from core.config import Config
from core.exceptions import EmailError, RegisterError
from core.logger import log_begin, log_complete, log_stats, logger
from services.email_manager import EmailAccount, EmailManager
from services.email_monitor import get_email_monitor
from services.fetch_manager import FetchManager
from services.phone_service import PhoneVerificationService
from services.uuid import ULID

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def extract_jwt(cookie_string: str) -> str:
    """从cookie字符串中提取JWT token"""
    try:
        # 先提取纯cookie值
        pure_cookie = extract_cookie(cookie_string)
        # 然后从纯cookie中提取JWT部分
        return pure_cookie.split("%3A%3A")[1]
    except Exception as e:
        logger.error(f"[错误] 提取JWT失败: {str(e)}")
        return ""


def extract_cookie(cookie_string: str) -> str:
    """从完整cookie字符串中提取纯cookie值，去掉前缀和后缀"""
    try:
        # 去掉前缀 "WorkosCursorSessionToken="
        if "WorkosCursorSessionToken=" in cookie_string:
            cookie_string = cookie_string.replace("WorkosCursorSessionToken=", "")

        # 去掉后缀 "; Path=/; HttpOnly; Secure; SameSite=Lax"
        if "; Path=" in cookie_string:
            cookie_string = cookie_string.split("; Path=")[0]

        return cookie_string
    except Exception as e:
        logger.error(f"[错误] 提取纯cookie值失败: {str(e)}")
        return cookie_string  # 返回原始字符串作为后备


class FormBuilder:
    @staticmethod
    def _generate_password() -> str:
        """生成随机密码
        规则: 12-16位，包含大小写字母、数字和特殊字符
        """
        length = random.randint(12, 16)
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*"

        # 确保每种字符至少有一个
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special),
        ]

        # 填充剩余长度
        all_chars = lowercase + uppercase + digits + special
        password.extend(random.choice(all_chars) for _ in range(length - 4))

        # 打乱顺序
        random.shuffle(password)
        return "".join(password)

    @staticmethod
    def _generate_name() -> tuple[str, str]:
        """生成随机的名字和姓氏
        Returns:
            tuple: (first_name, last_name)
        """
        first_names = [
            "Alex",
            "Sam",
            "Chris",
            "Jordan",
            "Taylor",
            "Morgan",
            "Casey",
            "Drew",
            "Pat",
            "Quinn",
        ]
        last_names = [
            "Smith",
            "Johnson",
            "Brown",
            "Davis",
            "Wilson",
            "Moore",
            "Taylor",
            "Anderson",
            "Thomas",
            "Jackson",
        ]

        return (random.choice(first_names), random.choice(last_names))

    @staticmethod
    def build_register_form(
        boundary: str, email: str, token: str, first_name: str, last_name: str
    ) -> tuple[str, str]:
        """构建注册表单数据，返回(form_data, password)"""
        password = FormBuilder._generate_password()

        fields = {
            "1_state": '{"returnTo":"/settings"}',
            "1_redirect_uri": "https://cursor.com/api/auth/callback",
            "1_bot_detection_token": token,
            "1_first_name": first_name,
            "1_last_name": last_name,
            "1_email": email,
            "1_password": password,
            "1_intent": "sign-up",
            "0": '["$K1"]',
        }

        form_data = []
        for key, value in fields.items():
            form_data.append(f"--{boundary}")
            form_data.append(f'Content-Disposition: form-data; name="{key}"')
            form_data.append("")
            form_data.append(value)

        form_data.append(f"--{boundary}--")
        return "\r\n".join(form_data), password

    @staticmethod
    def build_verify_form(
        boundary: str, email: str, token: str, code: str, pending_token: str
    ) -> str:
        """构建验证表单数据"""
        fields = {
            "1_pending_authentication_token": pending_token,
            "1_email": email,
            "1_state": '{"returnTo":"/settings"}',
            "1_redirect_uri": "https://cursor.com/api/auth/callback",
            "1_bot_detection_token": token,
            "1_code": code,
            "0": '["$K1"]',
        }

        form_data = []
        for key, value in fields.items():
            form_data.append(f"--{boundary}")
            form_data.append(f'Content-Disposition: form-data; name="{key}"')
            form_data.append("")
            form_data.append(value)

        form_data.append(f"--{boundary}--")
        return "\r\n".join(form_data)


class RegisterWorker:
    def __init__(
        self, config: Config, fetch_manager: FetchManager, email_manager: EmailManager
    ):
        self.config = config
        self.fetch_manager = fetch_manager
        self.email_manager = email_manager
        self.form_builder = FormBuilder()
        self.uuid = ULID()
        self.wuid = None

        # 初始化椰子手机验证服务
        if config.phone_service_config.enabled:
            self.phone_service = PhoneVerificationService(config, self.fetch_manager)
            logger.info("椰子手机验证服务已启用")
        else:
            self.phone_service = None
            logger.debug("椰子手机验证服务未启用")

    async def random_delay(self):
        delay = random.uniform(*self.config.register_config.delay_range)
        await asyncio.sleep(delay)

    def generate_random_hash(self):
        """生成随机的指纹哈希"""
        random_bytes = get_random_bytes(32)
        random_hex = random_bytes.hex()
        return random_hex

    async def get_webkit_fingerprint(self, proxy: str, session_id: str) -> str:
        """获取WebKit指纹，返回__wuid值"""

        fingerprint_hash = self.generate_random_hash()
        payload_list = f'["{fingerprint_hash}"]'

        url = f"https://authenticator.cursor.sh/?client_id=client_01GS6W3C96KW4WRS6Z93JCE2RJ&redirect_uri=https%3A%2F%2Fcursor.com%2Fapi%2Fauth%2Fcallback&response_type=code&state=%257B%2522returnTo%2522%253A%2522%252Fsettings%2522%257D&authorization_session_id={session_id}"

        headers = {
            "next-action": "a67eb6646e43eddcbd0d038cbee664aac59f5a53",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": '"127.0.6533.120"',
            "sec-ch-ua-model": '""',
            "sec-ch-ua-platform-version": '"15.0.0"',
            "content-type": "text/plain;charset=UTF-8",
        }
        response = await self.fetch_manager.request(
            "POST", url, headers=headers, data=payload_list, proxy=proxy
        )
        if "error" in response:
            logger.error(f"获取WebKit指纹失败: {response['error']}")
            return None

        text = response["body"].decode()
        wuid = None

        for line in text.split("\n"):
            if line.startswith("1:"):
                try:
                    json_data = json.loads(line.replace("1:", ""))
                    wuid = json_data.get("payload")
                    # logger.debug(f"成功提取WebKit指纹: {wuid[:10]}...")
                    break
                except Exception:
                    # logger.error(f"解析WebKit响应失败: {str(e)}")
                    ...

        return wuid

    @staticmethod
    async def _extract_auth_token(
        response_text: str, email_account: EmailAccount, email_manager: EmailManager
    ) -> str | None:
        """从响应文本中提取pending_authentication_token"""
        res = response_text.split("\n")
        # logger.debug(f"开始提取 auth_token，响应行数: {len(res)}")

        # 检查邮箱是否可用
        for line in res:
            if '"code":"email_not_available"' in line:
                logger.error("不受支持的邮箱")
                await email_manager.update_account_status(
                    email_account.id, "unavailable"
                )
                raise RegisterError("Email is not available")

        try:
            for r in res:
                if r.startswith("0:"):
                    # logger.debug(f"在第 {i+1} 行找到匹配")
                    data = json.loads(r.split("0:")[1])
                    auth_data = data[1][0][0][1]["children"][1]["children"][1][
                        "children"
                    ][1]["children"][0]
                    params_str = auth_data.split("?")[1]
                    params_dict = json.loads(params_str)
                    token = params_dict["pending_authentication_token"]
                    # logger.debug(f"方法2提取成功: {token[:10]}...")
                    return token
        except Exception:
            # logger.error(f"提取token失败: {str(e)}")
            # logger.debug("响应内容预览:", response_text[:200])
            ...

        return None

    def generate_code_verifier(self):
        """生成随机的32字节数据并进行base64url编码作为code_verifier"""
        random_bytes = secrets.token_bytes(32)
        code_verifier = base64.urlsafe_b64encode(random_bytes).decode("utf-8")
        # 移除填充字符
        code_verifier = code_verifier.rstrip("=")
        return code_verifier

    def generate_code_challenge(self, code_verifier):
        """根据code_verifier计算code_challenge"""
        # 计算SHA256哈希
        sha256_hash = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        # 进行base64url编码
        code_challenge = base64.urlsafe_b64encode(sha256_hash).decode("utf-8")
        # 移除填充字符
        code_challenge = code_challenge.rstrip("=")
        return code_challenge

    async def get_client_token(self, cookies_str, proxy=None):
        """获取完整的client token"""
        # 生成随机参数
        random_verifier = self.generate_code_verifier()
        random_challenge = self.generate_code_challenge(random_verifier)
        random_uuid = str(uuid.uuid4())

        # 从cookies字符串中提取cookie值
        session_token = extract_cookie(cookies_str)

        # 发送认证回调请求
        headers = {
            "accept": "*/*",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7",
            "cache-control": "no-cache",
            "content-type": "application/json",
            "origin": "https://www.cursor.com",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "referer": f"https://www.cursor.com/cn/loginDeepControl?challenge={random_challenge}&uuid={random_uuid}&mode=login",
            "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
        }

        cookies = {
            "NEXT_LOCALE": "cn",
            "WorkosCursorSessionToken": session_token,
        }

        url = "https://www.cursor.com/api/auth/loginDeepCallbackControl"
        data = {
            "uuid": random_uuid,
            "challenge": random_challenge,
        }

        # 发送请求初始化验证过程
        response = await self.fetch_manager.request(
            "POST", url, headers=headers, json=data, proxy=proxy, cookies=cookies
        )

        if "error" in response:
            logger.error(f"初始化验证过程失败: {response['error']}")
            return None

        # 开始轮询获取token
        poll_url = f"https://api2.cursor.sh/auth/poll?uuid={random_uuid}&verifier={random_verifier}"

        poll_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Cursor/0.48.6 Chrome/132.0.6834.210 Electron/34.3.4 Safari/537.36",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "sec-ch-ua-platform": '"Windows"',
            "x-ghost-mode": "true",
            "x-new-onboarding-completed": "false",
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132"',
            "sec-ch-ua-mobile": "?0",
            "origin": "vscode-file://vscode-app",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "accept-language": "zh-CN",
            "priority": "u=1, i",
        }

        max_attempts = 15  # 最多尝试15次
        retry_interval = 5  # 每5秒尝试一次

        for _ in range(max_attempts):
            try:
                poll_response = await self.fetch_manager.request(
                    "GET", poll_url, headers=poll_headers, proxy=proxy
                )

                if "error" in poll_response:
                    logger.error(f"轮询请求失败: {poll_response['error']}")
                    await asyncio.sleep(retry_interval)
                    continue

                # 直接尝试解析响应体，不依赖状态码
                try:
                    response_text = poll_response["body"].decode()

                    response_data = json.loads(response_text)
                    if "accessToken" in response_data:
                        access_token = response_data.get("accessToken")
                        auth_id = response_data.get("authId")

                        if access_token and auth_id:
                            # 从authId中提取user_id部分
                            user_id = auth_id.split("|")[1]
                            # 构建cursor_cookie格式
                            full_cookie = f"{user_id}%3A%3A{access_token}"
                            return {
                                "access_token": access_token,
                                "refresh_token": response_data.get("refreshToken"),
                                "full_cookie": full_cookie,
                            }
                        else:
                            logger.error("响应中未包含必要的token信息")
                            continue
                    else:
                        logger.debug("轮询未获取到token，等待下一次尝试...")
                except json.JSONDecodeError:
                    logger.error(f"响应不是有效的JSON: {response_text}")
                except Exception as e:
                    logger.error(f"处理轮询响应时出错: {str(e)}")

                # 等待再次尝试
                await asyncio.sleep(retry_interval)

            except Exception as e:
                logger.error(f"轮询过程出错: {str(e)}")

            # 等待再次尝试
            await asyncio.sleep(retry_interval)

        logger.error("轮询获取token失败，已达到最大尝试次数")
        return None

    async def register(
        self, proxy: str, token_pair: Tuple[str, str], email_account: EmailAccount
    ):
        """完整的注册流程"""
        token1, token2 = token_pair
        session_id = self.uuid.generate()
        try:
            # 获取WebKit指纹
            self.wuid = await self.get_webkit_fingerprint(proxy, session_id)

            # 第一次注册请求
            try:
                email, pending_token, cursor_password = await self._first_register(
                    proxy,
                    token1,
                    email_account.email,
                    email_account,
                    session_id=session_id,
                )
            except RegisterError as e:
                if "Email is not available" in str(e):
                    logger.warning(
                        f"{logger.symbols['skip']} 邮箱 {email_account.email} 不受支持，跳过处理"
                    )
                    return None
                raise e

            # 获取验证码的同时，可以开始准备下一步的操作
            verification_code_task = self._get_verification_code_with_retry(
                email_account.email,
                email_account.refresh_token,
                email_account.client_id,
                email_account.id,
            )

            # 等待验证码
            verification_code = await verification_code_task
            if not verification_code:
                logger.error(
                    f"{logger.symbols['error']} 账号 {email_account.email} 获取验证码失败"
                )
                await self.email_manager.update_account_status(
                    email_account.id, "failed"
                )
                raise RegisterError("Failed to get verification code")

            logger.debug(
                f"邮箱 {email_account.email} 获取到验证码: {verification_code}"
            )

            await self.random_delay()

            # 验证码验证
            redirect_url = await self._verify_code(
                proxy=proxy,
                token=token2,
                code=verification_code,
                pending_token=pending_token,
                email=email,
                session_id=session_id,
            )

            if not redirect_url:
                raise RegisterError("No redirect URL found")

            await self.random_delay()

            # callback请求
            cookies = await self._callback(proxy, redirect_url)
            # 修改: 如果没有cookie，不抛出异常，而是设置special_status
            special_status = None
            token_data = None

            if not cookies:
                logger.warning(
                    f"{logger.symbols['warning']} 账号 {email_account.email} 注册成功但获取Cookie失败"
                )
                special_status = "cookie_failed"
            else:
                # 获取完整token
                token_data = await self.get_client_token(cookies, proxy)
                if not token_data:
                    logger.warning(
                        f"{logger.symbols['warning']} 账号 {email_account.email} 注册成功但获取Token失败"
                    )
                    special_status = "token_failed"

            # 构建返回结果
            if special_status:
                # 注册成功但cookie或token获取失败
                logger.info(
                    f"{logger.symbols['info']} 账号 {email_account.email} 注册部分成功，状态: {special_status}"
                )
                return {
                    "account_id": email_account.id,
                    "email": email_account.email,
                    "cursor_password": cursor_password,
                    "cursor_cookie": "",  # 空cookie
                    "cursor_token": "",  # 空token
                    "refresh_token": "",  # 空refresh_token
                    "special_status": special_status,  # 添加特殊状态标记
                }
            else:
                # 完全成功
                logger.success(
                    f"{logger.symbols['success']} 账号 {email_account.email} 注册成功"
                )
                return {
                    "account_id": email_account.id,
                    "email": email_account.email,
                    "cursor_password": cursor_password,
                    "cursor_cookie": token_data["full_cookie"],
                    "cursor_token": token_data["access_token"],
                    "refresh_token": token_data["refresh_token"],
                }

        except Exception as e:
            logger.error(
                f"{logger.symbols['fail']} 账号 {email_account.email} 注册失败: {str(e)}"
            )
            if not str(e).startswith("Email is not available"):
                await self.email_manager.update_account_status(
                    email_account.id, "failed"
                )
            raise RegisterError(f"Registration failed: {str(e)}")

    async def _first_register(
        self,
        proxy: str,
        token: str,
        email: str,
        email_account: EmailAccount,
        session_id: str,
    ) -> tuple[str, str, str]:
        """第一次注册请求"""
        logger.debug(f"开始第一次注册请求 - 邮箱: {email}, 代理: {proxy}")

        first_name, last_name = self.form_builder._generate_name()

        # 在headers中定义boundary
        boundary = "----WebKitFormBoundary2rKlvTagBEhneWi3"
        headers = {
            "accept": "text/x-component",
            "next-action": "770926d8148e29539286d20e1c1548d2aff6c0b9",
            "content-type": f"multipart/form-data; boundary={boundary}",
            "origin": "https://authenticator.cursor.sh",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }

        # 如果有WebKit指纹，添加到Cookie
        if self.wuid:
            headers["Cookie"] = f"__wuid={self.wuid}"
            # logger.debug("已将WebKit指纹添加到Cookie")

        params = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "state": "%7B%22returnTo%22%3A%22%2Fsettings%22%7D",
            "redirect_uri": "https://cursor.com/api/auth/callback",
            "authorization_session_id": session_id,
        }

        # 构建form数据
        form_data, cursor_password = self.form_builder.build_register_form(
            boundary, email, token, first_name, last_name
        )

        response = await self.fetch_manager.request(
            "POST",
            "https://authenticator.cursor.sh/sign-up/password",
            headers=headers,
            params=params,
            data=form_data,
            proxy=proxy,
        )

        if "error" in response:
            raise RegisterError(f"First register request failed: {response['error']}")

        text = response["body"].decode()
        pending_token = await self._extract_auth_token(
            text, email_account, self.email_manager
        )
        if not pending_token:
            raise RegisterError("Failed to extract token")
        return email, pending_token, cursor_password

    async def _verify_code(
        self,
        proxy: str,
        token: str,
        code: str,
        pending_token: str,
        email: str,
        session_id: str,
    ) -> str:
        """验证码验证请求"""
        logger.debug(f"开始验证码验证 - 邮箱: {email}, 验证码: {code}")

        boundary = "----WebKitFormBoundaryqEBf0rEYwwb9aUoF"
        headers = {
            "accept": "text/x-component",
            "content-type": f"multipart/form-data; boundary={boundary}",
            "next-action": "e75011da58d295bef5aa55740d0758a006468655",
            "origin": "https://authenticator.cursor.sh",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        }

        if self.wuid:
            headers["Cookie"] = f"__wuid={self.wuid}"

        params = {
            "email": email,
            "pending_authentication_token": pending_token,
            "state": "%7B%22returnTo%22%3A%22%2Fsettings%22%7D",
            "redirect_uri": "https://cursor.com/api/auth/callback",
            "authorization_session_id": session_id,
        }

        form_data = self.form_builder.build_verify_form(
            boundary=boundary,
            email=email,
            token=token,
            code=code,
            pending_token=pending_token,
        )

        response = await self.fetch_manager.request(
            "POST",
            "https://authenticator.cursor.sh/email-verification",
            headers=headers,
            params=params,
            data=form_data,
            proxy=proxy,
        )

        redirect_url = response.get("headers", {}).get("x-action-redirect")
        if not redirect_url:
            raise RegisterError(
                "未找到重定向URL，响应头: %s" % json.dumps(response.get("headers"))
            )

        # 检测是否需要手机验证
        if "/radar-challenge/send" in redirect_url:
            logger.debug(f"\n\n\n{redirect_url}\n\n\n")
            logger.info(f"检测到需要手机验证，启动椰子手机验证服务 - 邮箱: {email}")

            if not self.phone_service:
                raise RegisterError("需要手机验证但椰子手机验证服务未启用")

            try:
                # 使用椰子手机验证服务处理手机验证
                final_redirect_url = await self.phone_service.handle_phone_verification(
                    redirect_url=redirect_url, wuid=self.wuid, proxy=proxy
                )

                if final_redirect_url:
                    logger.info(f"椰子手机验证成功 - 邮箱: {email}")
                    return final_redirect_url
                else:
                    raise RegisterError("最终回调地址获取失败")

            except Exception as e:
                logger.error(f"椰子手机验证过程失败 - 邮箱: {email}, 错误: {str(e)}")
                raise RegisterError(f"椰子手机验证失败: {str(e)}")

        return redirect_url

    async def _callback(self, proxy: str, redirect_url: str) -> str:
        """Callback请求"""
        logger.debug(f"开始callback请求 - URL: {redirect_url[:50]}...")

        parsed = urlparse(redirect_url)
        code = parse_qs(parsed.query)["code"][0]

        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-language": "zh-CN,zh;q=0.9",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        }

        if self.wuid:
            headers["Cookie"] = f"__wuid={self.wuid}"

        callback_url = "https://www.cursor.com/api/auth/callback"
        params = {"code": code, "state": "%7B%22returnTo%22%3A%22%2Fsettings%22%7D"}

        response = await self.fetch_manager.request(
            "GET",
            callback_url,
            headers=headers,
            params=params,
            proxy=proxy,
            allow_redirects=False,
        )

        if "error" in response:
            raise RegisterError(f"Callback request failed: {response['error']}")

        cookies = response["headers"].get("set-cookie")
        return cookies

    async def _get_verification_code_with_retry(
        self, email: str, refresh_token: str, client_id: str, account_id: int
    ) -> Optional[str]:
        """带重试的验证码获取"""
        try:
            code = await self.email_manager.get_verification_code(
                email, refresh_token, client_id
            )
            if code:
                return code
            logger.warning(f"[{email}] 获取验证码失败: 未返回有效验证码")
            return None
        except EmailError as e:
            error_msg = str(e)
            # 细化错误处理：区分不同类型的错误
            if "Failed to get access token" in error_msg:
                logger.error(f"[{email}] 获取access token失败: {error_msg}")
                # token获取失败时，将账号状态更新为unavailable
                await self.email_manager.update_account_status(
                    account_id, "unavailable"
                )
                return None
            elif "connect to Outlook server" in error_msg:
                logger.error(f"[{email}] 连接Outlook服务器失败: {error_msg}")
                # 连接失败时，将账号状态更新为unavailable
                await self.email_manager.update_account_status(
                    account_id, "unavailable"
                )
                return None
            else:
                logger.warning(f"[{email}] 获取验证码失败: {error_msg}")
                return None
        except Exception as e:
            logger.warning(f"[{email}] 获取验证码失败: {str(e)}")
            return None

    async def register_batch(
        self,
        proxies: List[str],
        token_pairs: List[Tuple[str, str]],
        accounts: List[Any],
    ) -> List[Dict]:
        """批量注册账号，使用共享的邮件监控服务提高效率"""
        batch_id = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        batch_start_time = time.time()
        log_begin(f"批次[{batch_id}] 开始注册 {len(accounts)} 个账号")

        # 确保邮件监控服务已启动
        if self.config.qq_imap_config.enabled:
            await get_email_monitor(self.config)
            logger.debug("邮件监控服务已就绪")

        # 创建任务列表
        tasks = []
        for account, proxy, token_pair in zip(accounts, proxies, token_pairs):
            task = self.register(proxy, token_pair, account)
            tasks.append(task)

        # 直接执行所有任务，不再分批
        results = []
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理结果
        successful = []
        failed = []
        skipped = 0

        for result in results:
            if isinstance(result, Exception):
                failed.append(str(result))
            elif result is None:
                skipped += 1
            else:
                successful.append(result)

        # 计算执行时间和速率
        batch_time = time.time() - batch_start_time
        accounts_per_minute = (
            len(successful) / (batch_time / 60) if batch_time > 0 else 0
        )

        # 输出统计信息
        log_complete(f"批次[{batch_id}] 完成，耗时: {batch_time:.1f}秒")
        log_stats(
            f"批次[{batch_id}] 统计: 成功={len(successful)}/{len(accounts)} ({len(successful) / len(accounts) * 100:.1f}%), 失败={len(failed)}, 跳过={skipped}"
        )
        log_stats(f"批次[{batch_id}] 性能: {accounts_per_minute:.2f}账号/分钟")

        return successful
