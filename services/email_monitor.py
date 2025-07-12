import asyncio
import email
import imaplib
import re
import time
from dataclasses import dataclass
from email.header import decode_header, make_header
from typing import Any, List, Optional

from core.config import Config
from core.logger import logger


@dataclass
class VerificationEmail:
    email_id: str
    from_address: str
    to_address: str
    subject: str
    verification_code: Optional[str]
    received_time: float
    raw_content: Any  # 原始邮件内容


class EmailMonitorService:
    """集中式邮件监控服务，负责持续监控邮箱并提取验证码"""

    def __init__(self, config: Config):
        self.config = config
        self._qq_imap = None
        self._is_connected = False
        self._running = False
        self._monitor_task = None

        # 邮件缓存和等待队列
        self._email_cache = {}  # email_id -> VerificationEmail
        self._pending_verifications = {}  # target_email -> asyncio.Future

        # 上次检索时间和处理状态
        self._last_check_time = 0
        self._checked_ids = set()  # 已检查过的邮件ID

        # 邮件监控锁，防止并发访问
        self._monitor_lock = asyncio.Lock()

        # 验证邮件主题关键词
        self.verification_subjects = [
            "Verify your email",
            "Complete code challenge",
            "Verify your email address",
        ]

    async def start(self):
        """启动邮件监控服务"""
        if self._running:
            return

        self._running = True
        await self._connect()

        # 创建监控任务
        self._monitor_task = asyncio.create_task(self._monitor_emails())
        logger.info("邮件监控服务已启动")

    async def stop(self):
        """停止邮件监控服务"""
        if not self._running:
            return

        self._running = False

        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        if self._is_connected and self._qq_imap:
            try:
                self._qq_imap.close()
                self._qq_imap.logout()
            except Exception as e:
                logger.error(f"关闭IMAP连接出错: {str(e)}")

        self._is_connected = False
        logger.info("邮件监控服务已停止")

    async def get_verification_code(
        self, target_email: str, timeout: int = None
    ) -> Optional[str]:
        """
        获取指定邮箱的验证码

        Args:
            target_email: 目标邮箱地址
            timeout: 超时时间(秒)，如果不指定则使用默认值90秒

        Returns:
            验证码字符串或None(获取失败)
        """
        # 如果未指定超时时间，使用默认值
        if timeout is None:
            timeout = 90

        # 首先检查缓存中是否已经有此邮箱的验证码
        verification_code = self._check_cache_for_email(target_email)
        if verification_code:
            logger.info(f"[{target_email}] 在缓存中找到验证码: {verification_code}")
            return verification_code

        # 创建Future用于等待验证码
        future = asyncio.get_running_loop().create_future()
        self._pending_verifications[target_email] = future

        try:
            # 等待验证码，设置超时
            logger.info(f"[{target_email}] 等待验证码, 超时时间: {timeout}秒")
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            logger.warning(f"[{target_email}] 等待验证码超时")
            return None
        finally:
            # 清理，从等待队列中移除
            if target_email in self._pending_verifications:
                del self._pending_verifications[target_email]

    def _check_cache_for_email(self, target_email: str) -> Optional[str]:
        """检查缓存中是否有目标邮箱的验证码"""
        current_time = time.time()
        # 扩大检查窗口到15分钟
        recent_time = current_time - 900  # 15分钟 = 900秒

        logger.debug(
            f"[{target_email}] 开始检查邮件缓存，缓存数量: {len(self._email_cache)}"
        )

        for email_obj in self._email_cache.values():
            logger.debug(
                f"检查缓存邮件: To={email_obj.to_address}, Code={email_obj.verification_code}, Time={email_obj.received_time}"
            )
            # 检查是否是近期邮件且发送给目标邮箱
            if email_obj.received_time >= recent_time:
                if target_email in email_obj.to_address:
                    logger.info(f"[{target_email}] 在收件人中找到匹配")
                    return email_obj.verification_code
                elif (
                    email_obj.verification_code
                    and self._check_email_content_for_target(email_obj, target_email)
                ):
                    logger.info(f"[{target_email}] 在邮件内容中找到匹配")
                    return email_obj.verification_code

        logger.warning(f"[{target_email}] 未在缓存中找到匹配的验证码")
        return None

    def _check_email_content_for_target(
        self, email_obj: VerificationEmail, target_email: str
    ) -> bool:
        """检查邮件内容中是否包含目标邮箱地址"""
        if not email_obj.raw_content:
            return False

        try:
            # 提取邮件内容中的文本
            email_content = ""
            if email_obj.raw_content.is_multipart():
                for part in email_obj.raw_content.walk():
                    if part.get_content_type() in ["text/plain", "text/html"]:
                        try:
                            content = part.get_payload(decode=True).decode()
                            email_content += content
                        except:
                            pass
            else:
                try:
                    email_content = email_obj.raw_content.get_payload(
                        decode=True
                    ).decode()
                except:
                    pass

            # 检查内容中是否包含目标邮箱
            return target_email in email_content
        except Exception as e:
            logger.error(f"检查邮件内容出错: {str(e)}")
            return False

    async def _monitor_emails(self):
        """持续监控邮箱并处理新邮件"""
        check_interval = 2  # 每2秒检查一次新邮件

        while self._running:
            try:
                # 获取锁以防止并发访问
                async with self._monitor_lock:
                    if not self._is_connected:
                        await self._connect()

                    # 检查所有邮件文件夹
                    for folder in ["INBOX", "Junk"]:
                        # 选择邮件夹
                        self._qq_imap.select(folder)

                        # 使用SEARCH命令获取新邮件
                        # 优化搜索条件：只检索来自Cursor的未读邮件
                        search_cmd = f'(FROM "no-reply@cursor.sh" SINCE "{self._get_date_string()}" UNSEEN)'
                        status, data = self._qq_imap.search(None, search_cmd)

                        if status != "OK" or not data[0]:
                            continue

                        # 获取所有邮件ID
                        email_ids = data[0].split()

                        # 过滤出未处理的邮件
                        new_ids = [
                            id for id in email_ids if id not in self._checked_ids
                        ]

                        if new_ids:
                            logger.debug(f"发现 {len(new_ids)} 封未读邮件")

                            # 处理新邮件
                            await self._process_emails(folder, new_ids)
            except Exception as e:
                logger.error(f"监控邮件出错: {str(e)}")
                # 如果连接断开，尝试重新连接
                self._is_connected = False

            # 等待检查间隔
            await asyncio.sleep(check_interval)

    async def _process_emails(self, folder: str, email_ids: List[bytes]):
        """处理邮件并提取验证码"""
        for email_id in email_ids:
            try:
                # 标记为已检查
                self._checked_ids.add(email_id)

                # 获取邮件内容
                status, data = self._qq_imap.fetch(email_id, "(RFC822)")
                if status != "OK":
                    logger.warning(f"获取邮件 {email_id} 失败: status={status}")
                    continue

                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)

                # 提取邮件信息
                from_header = str(
                    make_header(decode_header(email_message.get("From", "")))
                )
                subject = str(
                    make_header(decode_header(email_message.get("Subject", "")))
                )
                to_header = str(make_header(decode_header(email_message.get("To", ""))))

                logger.debug(
                    f"处理新邮件: ID={email_id}, From={from_header}, To={to_header}, Subject={subject}"
                )

                # 检查是否是验证邮件
                if "Cursor" in from_header and any(
                    s in subject for s in self.verification_subjects
                ):
                    # 提取验证码
                    verification_code = self._extract_verification_code(email_message)

                    if verification_code:
                        logger.info(f"成功提取验证码: {verification_code}")
                        # 创建邮件对象并添加到缓存
                        email_obj = VerificationEmail(
                            email_id=email_id.decode(),
                            from_address=from_header,
                            to_address=to_header,
                            subject=subject,
                            verification_code=verification_code,
                            received_time=time.time(),
                            raw_content=email_message,
                        )

                        self._email_cache[email_id.decode()] = email_obj

                        # 清理旧缓存
                        self._clean_old_cache()

                        # 处理此邮件，尝试匹配等待中的验证请求
                        await self._match_verification_requests(email_obj)

                        logger.debug(
                            f"已处理验证邮件 ID:{email_id.decode()}, To:{to_header}, 验证码:{verification_code}"
                        )
                    else:
                        logger.warning(f"未能从邮件中提取到验证码: ID={email_id}")

                # 将邮件标记为已读，防止重复处理
                try:
                    self._qq_imap.store(email_id, "+FLAGS", "\\Seen")
                    logger.debug(f"邮件 ID:{email_id.decode()} 已标记为已读")
                except Exception as e:
                    logger.error(f"标记邮件为已读失败: {str(e)}")

            except Exception as e:
                logger.error(f"处理邮件 {email_id} 时出错: {str(e)}")
                logger.exception(e)  # 添加详细的异常堆栈信息

    async def _match_verification_requests(self, email_obj: VerificationEmail):
        """尝试匹配等待中的验证请求"""
        if not self._pending_verifications:
            logger.debug("没有待处理的验证请求")
            return

        logger.debug(
            f"开始匹配验证请求，当前待处理请求数: {len(self._pending_verifications)}"
        )

        # 首先检查收件人是否精确匹配
        exact_match = None
        for target_email, future in list(self._pending_verifications.items()):
            logger.debug(f"检查目标邮箱: {target_email}")

            if target_email in email_obj.to_address:
                exact_match = target_email
                if not future.done():
                    future.set_result(email_obj.verification_code)
                    logger.info(
                        f"[{target_email}] 找到精确匹配，验证码: {email_obj.verification_code}"
                    )
                break

        # 如果没有精确匹配，尝试检查邮件内容
        if not exact_match:
            logger.debug("未找到精确匹配，开始检查邮件内容")
            for target_email, future in list(self._pending_verifications.items()):
                if self._check_email_content_for_target(email_obj, target_email):
                    if not future.done():
                        future.set_result(email_obj.verification_code)
                        logger.info(
                            f"[{target_email}] 在邮件内容中找到匹配，验证码: {email_obj.verification_code}"
                        )
                    break
                else:
                    logger.debug(f"[{target_email}] 在邮件内容中未找到匹配")

    def _extract_verification_code(self, email_message) -> Optional[str]:
        """提取验证码"""
        try:
            # 尝试提取6位数字验证码
            email_content = ""

            # 处理多部分邮件
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain" or content_type == "text/html":
                        try:
                            payload = part.get_payload(decode=True).decode()
                            email_content += payload
                            logger.debug(f"成功解析邮件部分: {content_type}")
                        except Exception as e:
                            logger.error(f"解析邮件部分失败: {str(e)}")
                            continue
            else:
                # 处理单部分邮件
                try:
                    email_content = email_message.get_payload(decode=True).decode()
                    logger.debug("成功解析单部分邮件")
                except Exception as e:
                    logger.error(f"解析单部分邮件失败: {str(e)}")
                    pass

            # 使用正则表达式查找验证码
            # 先尝试查找6位数字验证码
            code_match = re.search(r"\b(\d{6})\b", email_content)
            if code_match:
                logger.info(f"找到6位数字验证码: {code_match.group(1)}")
                return code_match.group(1)

            # 如果没找到6位验证码，尝试查找4-8位数字验证码
            code_match = re.search(r"\b(\d{4,8})\b", email_content)
            if code_match:
                logger.info(f"找到4-8位数字验证码: {code_match.group(1)}")
                return code_match.group(1)

            # 如果没找到，尝试查找URL中的token参数
            url_match = re.search(r"token=([a-zA-Z0-9_-]+)", email_content)
            if url_match:
                logger.info(f"找到URL token: {url_match.group(1)}")
                return url_match.group(1)

            logger.warning("未找到任何验证码")
            return None
        except Exception as e:
            logger.error(f"提取验证码出错: {str(e)}")
            logger.exception(e)
            return None

    def _clean_old_cache(self):
        """清理旧的邮件缓存"""
        current_time = time.time()
        # 保留最近30分钟的邮件
        retention_time = current_time - 1800  # 30分钟 = 1800秒

        # 找出需要清理的邮件ID
        to_remove = []
        for email_id, email_obj in self._email_cache.items():
            if email_obj.received_time < retention_time:
                to_remove.append(email_id)

        # 从缓存中移除
        for email_id in to_remove:
            del self._email_cache[email_id]

        # 清理检查ID集合，保持在合理大小
        if len(self._checked_ids) > 1000:
            self._checked_ids = set()

    def _get_date_string(self) -> str:
        """获取今天的日期字符串，用于IMAP SEARCH命令"""
        from datetime import datetime

        return datetime.now().strftime("%d-%b-%Y")

    async def _connect(self):
        """连接到QQ邮箱IMAP服务器"""
        if self._is_connected:
            return

        try:
            logger.info(
                f"开始连接QQ邮箱IMAP服务器: {self.config.qq_imap_config.imap_server}:{self.config.qq_imap_config.imap_port}"
            )

            # 创建IMAP连接
            self._qq_imap = imaplib.IMAP4_SSL(
                self.config.qq_imap_config.imap_server,
                self.config.qq_imap_config.imap_port,
            )

            # 登录
            self._qq_imap.login(
                self.config.qq_imap_config.qq_email,
                self.config.qq_imap_config.qq_password,
            )

            self._is_connected = True
            logger.info(f"QQ邮箱IMAP登录成功: {self.config.qq_imap_config.qq_email}")

        except Exception as e:
            self._is_connected = False
            logger.error(f"连接QQ邮箱IMAP服务器失败: {str(e)}")
            raise Exception(f"Failed to connect to QQ IMAP: {str(e)}")


# 单例模式
_email_monitor_instance = None


async def get_email_monitor(config: Config) -> EmailMonitorService:
    """获取邮件监控服务实例（单例模式）"""
    global _email_monitor_instance

    if _email_monitor_instance is None:
        _email_monitor_instance = EmailMonitorService(config)
        await _email_monitor_instance.start()

    return _email_monitor_instance
