import asyncio
import email.header
import email.message
import email.parser
import re
from dataclasses import dataclass
from email.header import decode_header, make_header
from typing import List, Optional, Tuple

import aiohttp
from aioimaplib import IMAP4_SSL

from core.config import Config
from core.database import DatabaseManager
from core.exceptions import EmailError
from core.logger import logger
from services.email_monitor import get_email_monitor


@dataclass
class EmailAccount:
    id: int
    email: str
    password: str  # 这里实际上是 refresh_token
    client_id: str
    refresh_token: str
    in_use: bool = False
    cursor_password: Optional[str] = None
    cursor_cookie: Optional[str] = None
    sold: bool = False
    status: str = "pending"  # 新增状态字段: pending, unavailable, success


class EmailDecoder:
    """处理邮件解码相关的功能"""

    @staticmethod
    def decode_mime_header(header_value):
        """解码MIME格式的邮件头"""
        if not header_value:
            return ""

        return str(make_header(decode_header(header_value)))

    @staticmethod
    def get_plaintext_from_email(email_bytes):
        """从邮件数据中提取纯文本内容"""
        # 解析邮件
        parser = email.parser.BytesParser()
        msg = parser.parsebytes(email_bytes)

        # 优先获取纯文本内容
        plain_text = ""

        # 如果是多部分邮件
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        # 尝试不同编码解码内容
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            plain_text = payload.decode(charset)
                            break  # 找到纯文本内容后跳出循环
                        except UnicodeDecodeError:
                            try:
                                plain_text = payload.decode("utf-8", errors="replace")
                                break
                            except:
                                pass
                elif content_type == "text/html":
                    # 如果没有找到纯文本，也尝试从HTML中提取
                    payload = part.get_payload(decode=True)
                    if payload and not plain_text:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            html_content = payload.decode(charset)
                            # 这里可以实现一个简单的HTML到纯文本的转换
                            # 简化处理，仅去除HTML标签
                            plain_text = re.sub(r"<[^>]+>", " ", html_content)
                            break
                        except UnicodeDecodeError:
                            try:
                                html_content = payload.decode("utf-8", errors="replace")
                                plain_text = re.sub(r"<[^>]+>", " ", html_content)
                                break
                            except:
                                pass
        else:
            # 单部分邮件
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    try:
                        plain_text = payload.decode(charset)
                    except UnicodeDecodeError:
                        plain_text = payload.decode("utf-8", errors="replace")
            elif content_type == "text/html":
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    try:
                        html_content = payload.decode(charset)
                        plain_text = re.sub(r"<[^>]+>", " ", html_content)
                    except UnicodeDecodeError:
                        html_content = payload.decode("utf-8", errors="replace")
                        plain_text = re.sub(r"<[^>]+>", " ", html_content)

        return plain_text


class MicrosoftAuth:
    """处理微软OAuth认证相关的功能"""

    @staticmethod
    async def get_access_token(client_id: str, refresh_token: str) -> str:
        """获取微软 access token"""
        url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        data = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.post(url, data=data) as response:
                result = await response.json()

                if "error" in result:
                    error = result.get("error")
                    logger.error(f"获取 access token 失败: {error}")
                    raise EmailError(f"Failed to get access token: {error}")

                return result["access_token"]


class OutlookClient:
    """负责与Outlook邮箱交互的客户端"""

    def __init__(self, email: str, access_token: str, mailbox: str = "INBOX"):
        self.email = email
        self.access_token = access_token
        self.mailbox = mailbox
        self.client = None
        self.email_decoder = EmailDecoder()
        # 为每个文件夹单独维护已检查的UID缓存
        self.checked_uids = {}
        self._init_checked_uids()

    def _init_checked_uids(self):
        """初始化各文件夹的UID缓存"""
        for folder in ["INBOX", "JUNK"]:
            if folder not in self.checked_uids:
                self.checked_uids[folder] = set()

    async def connect(self):
        """连接到Outlook服务器并选择指定文件夹"""
        try:
            self.client = IMAP4_SSL("outlook.office365.com")
            await self.client.wait_hello_from_server()
            await self.client.xoauth2(self.email, self.access_token)
            await self.select_mailbox(self.mailbox)
        except Exception as e:
            logger.error(f"[{self.email}] 连接到Outlook服务器失败: {str(e)}")
            raise EmailError(f"Failed to connect to Outlook server: {str(e)}")

    async def select_mailbox(self, mailbox: str) -> bool:
        """选择指定的邮件文件夹"""
        try:
            result = await self.client.select(mailbox)
            if result.result != "OK":
                logger.warning(f"[{self.email}] 选择 {mailbox} 文件夹失败")
                return False
            self.mailbox = mailbox
            return True
        except Exception as e:
            logger.error(f"[{self.email}] 选择 {mailbox} 文件夹失败: {str(e)}")
            return False

    async def get_email_uids(self) -> List[str]:
        """获取当前选中文件夹中的所有邮件UID列表"""
        try:
            result = await self.client.uid_search("1:*", charset="us-ascii")

            if not result.lines or len(result.lines) < 1:
                logger.debug(f"[{self.email}] 在 {self.mailbox} 中未找到邮件")
                return []

            uids = result.lines[0].decode().split()
            if uids and uids[0] == "SEARCH":
                uids = uids[1:]

            return uids
        except Exception as e:
            logger.error(
                f"[{self.email}] 获取 {self.mailbox} 中的邮件UID列表失败: {str(e)}"
            )
            return []

    async def get_email_details(self, uid: str) -> Tuple[str, str, str, bytes]:
        """获取邮件详情"""
        try:
            # 获取邮件完整内容而不是分离获取
            fetch_result = await self.client.uid("FETCH", uid, "(RFC822)")
            if fetch_result.result != "OK" or not fetch_result.lines:
                logger.warning(f"[{self.email}] 获取邮件 {uid} 内容失败")
                return "", "", "", b""

            # 提取完整邮件数据
            full_email = b""
            capture_email = False
            for line in fetch_result.lines:
                line_str = line.decode("utf-8", errors="ignore")
                if "{" in line_str and "RFC822" in line_str:
                    capture_email = True
                    continue
                if capture_email:
                    full_email += line

            # 使用email模块解析
            from email import message_from_bytes

            email_message = message_from_bytes(full_email)

            # 解析头信息
            from_addr = self.email_decoder.decode_mime_header(
                email_message.get("From", "")
            )
            to_addr = self.email_decoder.decode_mime_header(email_message.get("To", ""))
            subject = self.email_decoder.decode_mime_header(
                email_message.get("Subject", "")
            )

            return from_addr, to_addr, subject, full_email
        except Exception as e:
            logger.error(f"[{self.email}] 获取邮件 {uid} 详情失败: {str(e)}")
            return "", "", "", b""

    async def search_verification_code(
        self, verification_subjects: List[str]
    ) -> Optional[str]:
        """在所有文件夹中搜索验证码"""
        folders_to_check = ["INBOX", "JUNK"]

        for folder in folders_to_check:
            try:
                if not await self.select_mailbox(folder):
                    continue

                code_finder = VerificationCodeFinder(self.email_decoder)

                # 尝试多次搜索
                for i in range(15):
                    # 获取所有邮件UID
                    uids = await self.get_email_uids()

                    if not uids:
                        if i == 0 or i == 4 or i == 9 or i == 14:
                            logger.debug(
                                f"[{self.email}] 在 {folder} 中未找到邮件，继续等待..."
                            )
                        await asyncio.sleep(1)
                        continue

                    # 过滤掉已经检查过的UID
                    new_uids = [
                        uid for uid in uids if uid not in self.checked_uids[folder]
                    ]

                    # 如果所有UID都已检查过，等待新邮件
                    if not new_uids:
                        if i == 0 or i == 4 or i == 9 or i == 14:
                            logger.debug(
                                f"[{self.email}] {folder} 中所有{len(uids)}封邮件都已检查过，等待新邮件..."
                            )
                        await asyncio.sleep(1)
                        continue

                    # 只分析最新的10封未检查过的邮件
                    newest_uids = sorted(new_uids, reverse=True)[:10]

                    # 逐个处理邮件
                    for uid in newest_uids:
                        try:
                            # 使用单一请求获取邮件详情
                            (
                                from_addr,
                                _,
                                subject,
                                full_email,
                            ) = await self.get_email_details(uid)

                            # 将当前UID添加到对应文件夹的已检查集合中
                            self.checked_uids[folder].add(uid)

                            # 只处理来自Cursor的邮件且主题匹配
                            if "no-reply@cursor.sh" in from_addr and any(
                                verify_subject in subject
                                for verify_subject in verification_subjects
                            ):
                                # 提取验证码
                                verification_code = code_finder.extract_code_from_email(
                                    full_email
                                )
                                if verification_code:
                                    return verification_code
                        except Exception as e:
                            logger.warning(
                                f"[{self.email}] 处理 {folder} 中的邮件 {uid} 时出错: {str(e)}"
                            )
                            # 即使处理出错，仍将UID添加到已检查集合，避免反复处理出错的邮件
                            self.checked_uids[folder].add(uid)
                            continue

                    # 当前循环中没有找到验证码，限制缓存大小，避免内存泄漏
                    if len(self.checked_uids[folder]) > 100:
                        logger.debug(
                            f"[{self.email}] {folder} 缓存大小超过100，清理旧的检查记录"
                        )
                        sorted_uids = sorted(self.checked_uids[folder])  # 按UID数值排序
                        self.checked_uids[folder] = set(
                            sorted_uids[-50:]
                        )  # 只保留最新的50个

                    # 等待一秒后重试
                    await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"[{self.email}] 在 {folder} 中搜索验证码时出错: {str(e)}")
                continue

        logger.warning(f"[{self.email}] 在所有文件夹中搜索后未找到验证码")
        return None

    async def close(self):
        """关闭连接"""
        if self.client:
            try:
                await self.client.close()
                await self.client.logout()
            except Exception as e:
                logger.error(f"[{self.email}] 关闭连接时出错: {str(e)}")


class VerificationCodeFinder:
    """负责从邮件中提取验证码"""

    def __init__(self, email_decoder: EmailDecoder):
        self.email_decoder = email_decoder

    def extract_code_from_email(self, email_bytes: bytes) -> Optional[str]:
        """从邮件中提取验证码"""
        try:
            plaintext = self.email_decoder.get_plaintext_from_email(email_bytes)

            # 1. 在HTML中查找包含6位数字的div
            match = re.search(r"<div[^>]*>(\d{6})</div>", plaintext)
            if match:
                code = match.group(1)
                logger.debug(f"从HTML中提取到验证码: {code}")
                return code

            # 2. 搜索6位数字验证码
            match = re.search(r"\b(\d{6})\b", plaintext)
            if match:
                code = match.group(1)
                return code

            # 3. 查找URL中的验证码参数
            url_match = re.search(r"token=([a-zA-Z0-9_-]+)", plaintext)
            if url_match:
                code = url_match.group(1)
                return code

            logger.warning("未能从邮件中提取到验证码")
            return None

        except Exception as e:
            logger.error(f"提取验证码失败: {str(e)}")
            return None


class EmailManager:
    def __init__(self, config: Config, db_manager: DatabaseManager):
        self.config = config
        self.db = db_manager
        self.verification_subjects = [
            "Verify your email",
            "Complete code challenge",
            "Verify your email address",
        ]
        # 添加缓存：记录已检查过的邮件ID
        self._checked_email_ids = set()
        # 每个邮箱账号的单独缓存
        self._email_account_caches = {}
        # 邮箱客户端缓存，避免重复创建连接
        self._outlook_clients = {}

    async def batch_get_accounts(self, num: int) -> List[EmailAccount]:
        """批量获取未使用的邮箱账号"""
        logger.info(f"尝试获取 {num} 个未使用的邮箱账号")

        query = """
            UPDATE email_accounts 
            SET in_use = 1, updated_at = CURRENT_TIMESTAMP
            WHERE id IN (
                SELECT id FROM email_accounts 
                WHERE in_use = 0 AND sold = 0 AND status = 'pending'
                LIMIT ?
            )
            RETURNING id, email, password, client_id, refresh_token
        """

        results = await self.db.fetch_all(query, (num,))
        logger.debug(f"实际获取到 {len(results)} 个账号")
        return [
            EmailAccount(
                id=row[0],
                email=row[1],
                password=row[2],
                client_id=row[3],
                refresh_token=row[4],
                in_use=True,
            )
            for row in results
        ]

    async def update_account_status(self, account_id: int, status: str):
        """更新账号状态"""
        query = """
            UPDATE email_accounts 
            SET 
                status = ?,
                in_use = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """
        await self.db.execute(query, (status, account_id))

    async def update_account(
        self,
        account_id: int,
        cursor_password: str,
        cursor_cookie: str,
        cursor_token: str,
        special_status: str = None,  # 添加特殊状态参数
    ):
        """更新账号信息"""
        # 根据special_status决定设置的状态
        status = "success"
        sold = 1

        # 如果有特殊状态，说明注册部分成功
        if special_status:
            if special_status == "cookie_failed" or special_status == "token_failed":
                status = "success\\NotCookie"  # 使用现有的status字段标记特殊状态
                sold = 0  # 不标记为已售出

        query = """
            UPDATE email_accounts 
            SET 
                cursor_password = ?, 
                cursor_cookie = ?, 
                cursor_token = ?,
                in_use = 0, 
                sold = ?,
                status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """
        await self.db.execute(
            query,
            (cursor_password, cursor_cookie, cursor_token, sold, status, account_id),
        )

    async def get_verification_code(
        self, email: str, refresh_token: str, client_id: str
    ) -> str:
        """获取验证码 - 支持原有Microsoft邮箱和QQ IMAP"""
        # 检查是否是自定义域名邮箱，判断是否使用QQ IMAP
        is_custom_domain = False
        if self.config.qq_imap_config.enabled:
            # 检查邮箱是否匹配任何一个配置的自定义域名
            for domain in self.config.qq_imap_config.domains:
                if email.endswith(f"@{domain}"):
                    is_custom_domain = True
                    break

            if is_custom_domain:
                logger.info(f"[{email}] 检测到自定义域名邮箱，使用QQ IMAP获取验证码")
                return await self._check_verification_from_qq_imap(email)

        # 如果不是自定义域名邮箱或QQ IMAP未启用，使用Microsoft邮箱获取验证码
        try:
            # 1. 获取 access token
            try:
                access_token = await MicrosoftAuth.get_access_token(
                    client_id, refresh_token
                )
            except EmailError as e:
                # 单独处理token获取失败的情况，提供明确的错误信息
                logger.error(f"[{email}] 获取access token失败: {str(e)}")
                # 包装一个明确的错误，便于上层识别
                raise EmailError(f"Failed to get access token: {str(e)}")

            # 2. 创建邮箱客户端
            outlook_client = OutlookClient(email, access_token)

            # 尝试连接，最多重试3次
            connected = False
            for attempt in range(3):
                try:
                    await outlook_client.connect()
                    connected = True
                    break  # 连接成功，跳出循环
                except Exception as e:
                    logger.error(f"[{email}] 连接到Outlook服务器失败: {str(e)}")
                    if attempt < 2:
                        logger.info(f"[{email}] 将在1秒后重试连接")
                        await asyncio.sleep(1)
                    else:
                        # 最后一次尝试也失败，直接抛出异常
                        raise EmailError(
                            f"Failed to connect to Outlook server after 3 attempts: {str(e)}"
                        )

            # 确保连接成功才继续
            if not connected:
                raise EmailError("Failed to connect to Outlook server")

            # 检查是否有该邮箱的缓存记录
            if email in self._email_account_caches:
                # 将缓存的已检查UID传给客户端
                outlook_client.checked_uids = self._email_account_caches[email]
                logger.debug(
                    f"[{email}] 从缓存中恢复了 {len(outlook_client.checked_uids)} 个已检查的邮件UID"
                )

            try:
                # 3. 搜索验证码
                code = await outlook_client.search_verification_code(
                    self.verification_subjects
                )

                # 保存已检查的UID到缓存
                self._email_account_caches[email] = outlook_client.checked_uids
                logger.debug(
                    f"[{email}] 已将 {len(outlook_client.checked_uids)} 个检查过的邮件UID保存到缓存"
                )

                if code:
                    return code
                else:
                    logger.error(f"[{email}] 验证码邮件未收到")
                    raise EmailError("Verification code not received")
            finally:
                # 4. 关闭连接
                try:
                    await outlook_client.close()
                except Exception as e:
                    logger.error(f"[{email}] 关闭连接时出错: {str(e)}")

        except Exception as e:
            logger.error(f"[{email}] 获取验证码失败: {str(e)}")
            raise EmailError(f"Failed to get verification code: {str(e)}")

    async def _check_verification_from_qq_imap(
        self, target_email: str
    ) -> Optional[str]:
        """从QQ邮箱IMAP获取验证码"""
        logger.info(f"[{target_email}] 开始从QQ邮箱获取验证码")

        try:
            # 使用集中式邮件监控服务
            email_monitor = await get_email_monitor(self.config)
            # 使用配置中的超时时间
            timeout = self.config.register_config.timeout
            verification_code = await email_monitor.get_verification_code(
                target_email, timeout=timeout
            )

            if verification_code:
                logger.info(f"[{target_email}] 成功获取验证码: {verification_code}")
                return verification_code
            else:
                logger.error(f"[{target_email}] 未能从QQ邮箱获取到验证码")
                return None
        except Exception as e:
            logger.error(f"[{target_email}] 获取验证码时出错: {str(e)}")
            return None
