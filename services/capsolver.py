import asyncio
import aiohttp
from core.logger import logger
from typing import Optional
import time

class Capsolver:
    def __init__(self, api_key: str, website_url: str, website_key: str):
        self.api_key = api_key
        self.website_url = website_url
        self.website_key = website_key
        self.base_url = "https://api.capsolver.com"

    async def create_task(self) -> Optional[str]:
        """创建验证码任务"""
        async with aiohttp.ClientSession() as session:
            payload = {
                "clientKey": self.api_key,
                "task": {
                    "type": "AntiTurnstileTaskProxyLess",
                    "websiteURL": self.website_url,
                    "websiteKey": self.website_key,
                }
            }
            
            async with session.post(f"{self.base_url}/createTask", json=payload) as resp:
                result = await resp.json()
                if result.get("errorId") > 0:
                    logger.error(f"创建任务失败: {result.get('errorDescription')}")
                    return None
                return result.get("taskId")

    async def get_task_result(self, task_id: str) -> Optional[dict]:
        """获取任务结果"""
        async with aiohttp.ClientSession() as session:
            payload = {
                "clientKey": self.api_key,
                "taskId": task_id
            }
            
            async with session.post(f"{self.base_url}/getTaskResult", json=payload) as resp:
                result = await resp.json()
                if result.get("errorId") > 0:
                    logger.error(f"获取结果失败: {result.get('errorDescription')}")
                    return None
                    
                if result.get("status") == "ready":
                    return result.get("solution", {})
                return None

    async def solve_turnstile(self) -> Optional[str]:
        """
        解决 Turnstile 验证码
        """
        task_id = await self.create_task()
        if not task_id:
            raise Exception("创建验证码任务失败")
        
        # 增加重试次数限制和超时时间控制
        max_retries = 5  # 减少最大重试次数
        retry_delay = 2  # 设置重试间隔为2秒
        timeout = 15     # 设置总超时时间为15秒
        
        start_time = time.time()
        for attempt in range(1, max_retries + 1):
            try:
                # logger.debug(f"第 {attempt} 次尝试获取验证码结果")
                result = await self.get_task_result(task_id)
                
                if result and "token" in result:
                    token = result["token"]
                    # logger.success(f"成功获取验证码 token: {token[:40]}...")
                    return token
                    
                # 检查是否超时
                if time.time() - start_time > timeout:
                    logger.error("验证码请求总时间超过15秒")
                    break
                    
                await asyncio.sleep(retry_delay)
                
            except Exception as e:
                logger.error(f"获取验证码结果失败: {str(e)}")
                if attempt == max_retries:
                    raise
                
                if time.time() - start_time > timeout:
                    logger.error("验证码请求总时间超过15秒")
                    break
                    
                await asyncio.sleep(retry_delay)
                
        raise Exception("验证码解决失败: 达到最大重试次数或超时") 