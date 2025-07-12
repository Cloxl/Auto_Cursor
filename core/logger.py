import sys
import threading
import os
import time

from loguru import logger as _logger  # 重命名导入避免冲突

from core.config import Config


# 使用标志和锁来确保单例
_logger_configured = False
_logger_lock = threading.Lock()


def setup_logger(config: Config = None):
    """
    配置日志系统，确保只配置一次（单例模式）
    如果已配置则直接返回logger对象，未配置则进行配置
    
    Args:
        config: 配置对象，可选
        
    Returns:
        logger: 配置好的logger对象
    """
    global _logger_configured, logger
    
    # 使用线程锁确保线程安全
    with _logger_lock:
        # 如果已经配置过，则直接返回
        if _logger_configured:
            return logger
        
        # 创建日志目录
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        
        # 日志文件路径 - 使用日期作为文件名
        log_file = os.path.join(log_dir, "cursor_{time:YYYY-MM-DD}.log")
        
        # 移除所有现有的处理器
        _logger.remove()
        
        # 添加控制台处理器 - 使用美化过的格式，但不添加自定义级别以避免冲突
        _logger.add(
            sys.stdout,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            level="DEBUG",
            colorize=True
        )
        
        # 添加文件处理器
        _logger.add(
            log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
            level="DEBUG",
            rotation="00:00",  # 每天午夜轮转
            retention="7 days",
            compression="zip",
            encoding="utf-8"
        )
        
        # 标记为已配置
        _logger_configured = True

    # 设置全局变量logger
    logger = _logger
    
    # 添加常用符号到logger对象，但不添加可能冲突的方法
    logger.symbols = {
        "success": "✅",
        "error": "❌",
        "warning": "⚠️",
        "info": "ℹ️",
        "debug": "🔍",
        "begin": "▶️",
        "done": "✓",
        "fail": "✗",
        "skip": "⏭️",
    }
    
    return logger


# 预配置一个logger实例
logger = setup_logger()

# 增加一些辅助函数，避免直接修改logger对象
def log_begin(message, *args, **kwargs):
    """记录开始事件"""
    logger.info(f"{logger.symbols['begin']} {message}", *args, **kwargs)

def log_complete(message, *args, **kwargs):
    """记录完成事件"""
    logger.success(f"✅ {message}", *args, **kwargs)

def log_progress(message, *args, **kwargs):
    """记录进度信息"""
    logger.info(f"🔄 {message}", *args, **kwargs)

def log_stats(message, *args, **kwargs):
    """记录统计信息"""
    logger.info(f"📊 {message}", *args, **kwargs)

# 将这些函数也暴露给导入模块
__all__ = ["logger", "setup_logger", "log_begin", "log_complete", "log_progress", "log_stats"]
