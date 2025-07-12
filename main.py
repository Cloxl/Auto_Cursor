import asyncio
import datetime
import random
import signal
import string
import sys
from typing import Dict, List

from core.config import Config
from core.database import DatabaseManager
from core.logger import log_begin, log_complete, log_stats, setup_logger
from register.register_worker import RegisterWorker
from services.email_manager import EmailManager
from services.fetch_manager import FetchManager
from services.proxy_pool import ProxyPool
from services.token_pool import TokenPool


class CursorRegister:
    def __init__(self):
        self.config = Config.from_yaml()
        self.logger = setup_logger(self.config)
        self.db_manager = DatabaseManager(self.config)
        self.fetch_manager = FetchManager(self.config)
        self.proxy_pool = ProxyPool(self.config, self.fetch_manager)
        self.token_pool = TokenPool(self.config)
        self.email_manager = EmailManager(self.config, self.db_manager)
        self.register_worker = RegisterWorker(
            self.config, self.fetch_manager, self.email_manager
        )
        # 添加退出标志
        self.shutdown_requested = False
        # 添加休息时间统计
        self.total_sleep_time = 0

    async def initialize(self):
        """初始化数据库"""
        await self.db_manager.initialize()

    async def cleanup(self):
        """清理资源"""
        await self.db_manager.cleanup()

    async def generate_random_emails(self, num: int) -> List[Dict]:
        """生成随机自定义域名邮箱并入库"""
        self.logger.info(f"开始生成 {num} 个随机自定义域名邮箱")

        # 从配置的域名列表中获取可用域名
        domains = self.config.qq_imap_config.domains
        if not domains:
            domains = ["mail.cloxl.com"]  # 默认域名，以防配置为空

        # 获取域名配额限制
        domain_quota = self.config.qq_imap_config.domain_quota

        # 如果设置了域名配额，需要检查每个域名的使用情况
        domain_usage = {}
        if domain_quota > 0:
            try:
                # 获取每个域名已使用的数量
                for domain in domains:
                    query = "SELECT COUNT(*) FROM email_accounts WHERE email LIKE ?"
                    result = await self.db_manager.fetch_one(query, (f"%@{domain}",))
                    domain_usage[domain] = result[0] if result else 0
                    self.logger.debug(
                        f"域名 {domain} 已使用数量: {domain_usage[domain]}"
                    )
            except Exception as e:
                self.logger.error(f"获取域名使用情况失败: {str(e)}")
                # 如果查询失败，默认所有域名未使用
                domain_usage = {domain: 0 for domain in domains}

        random_emails = []

        for _ in range(num):
            # 如果设置了域名配额，筛选未达到配额的域名
            available_domains = domains
            if domain_quota > 0:
                available_domains = [
                    d for d in domains if domain_usage.get(d, 0) < domain_quota
                ]

                # 如果所有域名都达到配额，记录错误并停止生成
                if not available_domains:
                    self.logger.error(
                        f"所有域名都已达到配额限制({domain_quota})，无法生成更多邮箱"
                    )
                    break

            # 随机选择一个可用域名
            domain = random.choice(available_domains)

            # 生成随机前缀 (10-15个字符)，只使用字母
            prefix = "".join(
                random.choices(string.ascii_lowercase, k=random.randint(10, 15))
            )
            email = f"{prefix}@{domain}"

            # 创建邮箱账号记录
            account = {
                "email": email,
                "password": "N/A",  # 必填非空字段给默认值
                "client_id": "N/A",
                "refresh_token": "N/A",
                "status": "pending",
            }
            random_emails.append(account)

            # 更新域名使用计数
            if domain_quota > 0:
                domain_usage[domain] = domain_usage.get(domain, 0) + 1

        return random_emails

    async def save_random_emails_to_db(self, emails: List[Dict]) -> bool:
        """将随机生成的邮箱保存到数据库"""
        self.logger.info(f"开始将 {len(emails)} 个随机邮箱保存到数据库")

        try:
            for account in emails:
                query = """
                    INSERT INTO email_accounts (
                        email, password, client_id, refresh_token, 
                        status, in_use, sold
                    ) VALUES (?, ?, ?, ?, ?, 0, 0)
                """
                await self.db_manager.execute(
                    query,
                    (
                        account["email"],
                        account["password"],
                        account["client_id"],
                        account["refresh_token"],
                        account["status"],
                    ),
                )

            self.logger.info(f"成功保存 {len(emails)} 个随机邮箱到数据库")
            return True
        except Exception as e:
            self.logger.error(f"保存随机邮箱到数据库失败: {str(e)}")
            return False

    async def batch_register(self, num: int):
        """批量注册 - 使用优化的并发策略和邮件监控服务"""
        try:
            log_begin(f"准备批量注册 {num} 个账号")

            # 1. 先获取token对
            self.logger.debug("正在获取token对...")
            token_pairs = await self.token_pool.batch_generate(num)
            if not token_pairs:
                self.logger.error(
                    f"{self.logger.symbols['error']} 获取token失败，终止注册"
                )
                return ([], 0)

            actual_num = len(token_pairs)  # 根据实际获取到的token对数量调整注册数量
            if actual_num < num:
                self.logger.warning(
                    f"{self.logger.symbols['warning']} 只获取到 {actual_num} 对token，将减少注册数量"
                )
                num = actual_num

            # 2. 获取邮箱账号
            self.logger.debug("正在获取邮箱账号...")
            email_accounts = await self.email_manager.batch_get_accounts(num)

            # 如果启用了QQ IMAP模式且没有获取到足够的邮箱账号，则生成随机邮箱
            if self.config.qq_imap_config.enabled and len(email_accounts) < num:
                missing_count = num - len(email_accounts)
                self.logger.info(f"需要额外生成 {missing_count} 个随机邮箱")

                # 生成随机邮箱并保存到数据库
                random_emails = await self.generate_random_emails(missing_count)
                success = await self.save_random_emails_to_db(random_emails)

                if success:
                    # 获取刚刚保存的随机邮箱
                    new_accounts = await self.email_manager.batch_get_accounts(
                        missing_count
                    )
                    if new_accounts:
                        email_accounts.extend(new_accounts)
                        self.logger.info(f"成功添加 {len(new_accounts)} 个随机邮箱")

            if len(email_accounts) < num:
                self.logger.warning(
                    f"{self.logger.symbols['warning']} 可用邮箱账号不足，仅获取到 {len(email_accounts)} 个"
                )
                num = len(email_accounts)

            if num == 0:
                self.logger.error(
                    f"{self.logger.symbols['error']} 没有可用的邮箱账号，无法进行注册"
                )
                return ([], 0)

            # 3. 获取代理
            self.logger.debug("正在获取代理...")
            proxies = await self.proxy_pool.batch_get(num)

            # 4. 使用新的批量注册方法
            self.logger.info(f"开始执行注册流程，账号数: {num}")
            successful = await self.register_worker.register_batch(
                proxies, token_pairs[:num], email_accounts
            )

            # 5. 更新数据库
            if successful:
                self.logger.debug(
                    f"更新数据库，记录 {len(successful)} 个成功账号信息..."
                )
                for result in successful:
                    try:
                        # 检查是否有特殊状态
                        special_status = result.get("special_status", None)
                        await self.email_manager.update_account(
                            result["account_id"],
                            result["cursor_password"],
                            result["cursor_cookie"],
                            result["cursor_token"],
                            special_status,  # 传递special_status参数
                        )
                    except Exception as e:
                        self.logger.error(
                            f"{self.logger.symbols['error']} 更新数据库失败 - 账号ID: {result['account_id']}, 错误: {str(e)}"
                        )

            # 返回成功注册的账号和实际尝试的账号数
            return (successful, num)

        except Exception as e:
            self.logger.error(f"{self.logger.symbols['error']} 批量注册失败: {str(e)}")
            return ([], 0)

    def request_shutdown(self):
        """请求程序优雅退出"""
        if not self.shutdown_requested:
            self.shutdown_requested = True
            self.logger.warning(
                f"{self.logger.symbols['warning']} 收到退出信号，将在当前批次完成后优雅退出..."
            )


async def main():
    register = CursorRegister()

    # 设置信号处理函数
    def signal_handler():
        register.request_shutdown()

    # 根据平台采用不同的信号处理方式
    loop = asyncio.get_running_loop()
    try:
        if sys.platform != "win32":
            # 在Unix/Linux平台上使用add_signal_handler
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, signal_handler)
            register.logger.debug("使用Unix信号处理机制")
        else:
            # Windows平台使用传统信号处理
            register.logger.debug("在Windows平台上使用传统信号处理机制")
            # Windows平台上不添加信号处理器，依赖于主循环中的检测
    except NotImplementedError:
        register.logger.warning("当前平台不支持asyncio信号处理，将使用默认处理机制")

    await register.initialize()

    try:
        batch_size = register.config.register_config.batch_size
        max_accounts = register.config.register_config.max_accounts
        max_concurrency = register.config.global_config.max_concurrency
        total_registered = 0
        successful_count = 0
        failed_count = 0
        batch_number = 0

        # 处理max_accounts为-1的情况，表示注册所有可用账户
        if max_accounts == -1:
            # 查询数据库获取可用账户总数
            try:
                # 如果启用了QQ IMAP模式，不需要预先检查数据库
                if register.config.qq_imap_config.enabled:
                    register.logger.info("QQ IMAP模式已启用，设置为无限注册模式")
                    max_accounts = 0  # 设置为0表示无限制
                else:
                    query = "SELECT COUNT(*) FROM email_accounts WHERE in_use = 0 AND sold = 0 AND status = 'pending'"
                    result = await register.db_manager.fetch_one(query)
                    if result and result[0] > 0:
                        all_available = result[0]
                        register.logger.info(
                            f"检测到max_accounts=-1，将注册所有 {all_available} 个可用账户"
                        )
                        max_accounts = all_available
                    else:
                        register.logger.warning(
                            "没有找到可用的邮箱账户，设置为无限注册模式"
                        )
                        max_accounts = 0  # 设置为0表示无限制
            except Exception as e:
                register.logger.error(
                    f"获取可用账户数量失败: {str(e)}，设置为无限注册模式"
                )
                max_accounts = 0  # 出错时设置为0表示无限制

        # 记录开始时间，用于日志
        start_time = datetime.datetime.now()
        log_begin(f"系统启动 - 时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # 显示配置信息，根据max_accounts值显示不同信息
        max_accounts_display = (
            "所有可用账户" if max_accounts == -1 else (max_accounts or "不限")
        )
        register.logger.info(
            f"配置信息 - 批次大小: {batch_size}, 最大注册账号数: {max_accounts_display}, 最大并发数: {max_concurrency}"
        )

        # 调整max_concurrency确保其不小于batch_size
        if max_concurrency < batch_size:
            register.logger.warning(
                f"最大并发数({max_concurrency})小于批次大小({batch_size})，自动调整最大并发数为 {batch_size}"
            )
            register.config.global_config.max_concurrency = batch_size

        while not register.shutdown_requested:
            # Windows平台需要特殊处理
            if sys.platform == "win32":
                # 通过这种方式允许在Windows上及时响应Ctrl+C
                await asyncio.sleep(0)

            # 检查是否达到最大注册数量（max_accounts > 0 表示有限制）
            if max_accounts > 0 and total_registered >= max_accounts:
                log_complete(f"已达到最大注册数量 {max_accounts}，注册完成")
                break

            # 计算本次批次需要注册的账号数
            current_batch_size = batch_size
            if max_accounts > 0:
                # 确保不超过最大注册数量
                remaining = max_accounts - total_registered
                if remaining < batch_size:
                    current_batch_size = remaining
                    register.logger.info(
                        f"调整批次大小至 {current_batch_size} 以匹配剩余配额"
                    )

            # 如果启用了QQ IMAP模式，不需要预先检查邮箱账号
            if register.config.qq_imap_config.enabled:
                register.logger.debug(
                    "QQ IMAP模式已启用，将使用随机生成的自定义域名邮箱"
                )
            else:
                # 原有逻辑：检查是否还有可用的邮箱账号
                available_accounts = await register.email_manager.batch_get_accounts(1)
                if not available_accounts:
                    register.logger.info("没有更多可用的邮箱账号，注册完成")
                    break

                # 释放检查用的账号
                await register.email_manager.update_account_status(
                    available_accounts[0].id, "pending"
                )

            # 更新批次编号
            batch_number += 1

            # 执行批量注册
            log_begin(f"执行批次 #{batch_number}，计划注册 {current_batch_size} 个账号")
            try:
                results, attempted_count = await register.batch_register(
                    current_batch_size
                )
            except Exception as e:
                register.logger.error(f"批次 #{batch_number} 执行失败: {str(e)}")
                # 出现异常时，等待一段时间后继续
                retry_interval = register.config.register_config.batch_interval
                if retry_interval <= 0:
                    retry_interval = 30  # 默认等待30秒
                register.logger.warning(f"等待 {retry_interval} 秒后重试下一批次...")
                await asyncio.sleep(retry_interval)
                continue

            # 如果token获取失败但没有抛出异常，只返回了空结果
            if results is None or (isinstance(results, tuple) and len(results) == 0):
                register.logger.warning(
                    f"批次 #{batch_number} 没有返回有效结果，可能是token获取失败"
                )
                # 等待一段时间后继续
                retry_interval = register.config.register_config.batch_interval
                if retry_interval <= 0:
                    retry_interval = 30  # 默认等待30秒
                register.logger.warning(f"等待 {retry_interval} 秒后重试下一批次...")
                await asyncio.sleep(retry_interval)
                continue

            # 更新统计信息
            batch_success = len(results)
            successful_count += batch_success
            failed_count += attempted_count - batch_success

            # 只计算实际尝试注册的账号数
            total_registered += attempted_count

            # 输出当前进度统计
            current_time = datetime.datetime.now()
            elapsed = (current_time - start_time).total_seconds() / 60  # 转换为分钟
            actual_elapsed = elapsed - (
                register.total_sleep_time / 60
            )  # 实际运行时间（减去休息时间）

            # 计算进度百分比
            progress_percent = 0
            if max_accounts > 0:
                progress_percent = (total_registered / max_accounts) * 100

            log_complete(
                f"批次 #{batch_number} 完成 - 成功: {batch_success}/{current_batch_size}"
            )
            log_stats(
                f"总体进度: {total_registered}/{max_accounts or '∞'} "
                f"({progress_percent:.1f}% 完成)"
                if max_accounts > 0
                else ""
            )
            log_stats(
                f"整体统计 - 成功: {successful_count}, 失败: {failed_count}, 成功率: {successful_count / total_registered * 100:.1f}%"
            )
            log_stats(
                f"运行时间: {elapsed:.1f}分钟 (实际工作时间: {actual_elapsed:.1f}分钟), "
                f"实际平均速度: {successful_count / actual_elapsed:.2f}账号/分钟"
            )

            # 批次间隔
            if not register.shutdown_requested and batch_number % 5 == 0:
                interval = register.config.register_config.batch_interval
                if interval > 0:
                    register.logger.info(f"每5个批次休息 {interval} 秒")
                    register.total_sleep_time += interval  # 记录休息时间
                    await asyncio.sleep(interval)

    except Exception as e:
        register.logger.error(f"主程序异常: {str(e)}")
    finally:
        # 记录结束统计
        end_time = datetime.datetime.now()
        elapsed = (end_time - start_time).total_seconds() / 60  # 转换为分钟
        actual_elapsed = elapsed - (
            register.total_sleep_time / 60
        )  # 实际运行时间（减去休息时间）

        log_complete(f"注册任务结束 - 时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        log_stats(
            f"最终统计 - 总注册: {total_registered}, 成功: {successful_count}, 失败: {failed_count}"
        )
        log_stats(
            f"总运行时间: {elapsed:.1f}分钟 (实际工作时间: {actual_elapsed:.1f}分钟), "
            f"实际平均速度: {successful_count / actual_elapsed:.2f}账号/分钟"
            if actual_elapsed > 0
            else "运行时间过短"
        )
        await register.cleanup()
        register.logger.info("程序已完成清理，正常退出")


if __name__ == "__main__":
    _register = None

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n程序被用户中断...")

        # 如果是在Windows平台上，可能需要手动清理
        if sys.platform == "win32":

            async def emergency_cleanup():
                try:
                    # 如果还没有注册器对象，创建一个新的
                    if "_register" not in globals() or not _register:
                        cleanup_register = CursorRegister()
                        print("正在进行紧急清理...")
                        await cleanup_register.initialize()
                        await cleanup_register.cleanup()
                    print("清理完成")
                except Exception as e:
                    print(f"清理过程出错: {e}")

            # 在新的事件循环中执行清理
            try:
                print("执行Windows平台特殊清理...")
                asyncio.run(emergency_cleanup())
            except Exception as e:
                print(f"清理过程失败: {e}")
    except Exception as e:
        print(f"\n程序出现未捕获的异常: {e}")
        import traceback

        traceback.print_exc()
    finally:
        print("程序已退出")
