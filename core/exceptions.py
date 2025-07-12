class CursorRegisterException(Exception):
    """基础异常类"""


class TokenGenerationError(CursorRegisterException):
    """Token生成失败"""


class ProxyFetchError(CursorRegisterException):
    """代理获取失败"""


class RegisterError(CursorRegisterException):
    """注册失败"""


class EmailError(CursorRegisterException):
    """邮件处理错误"""
