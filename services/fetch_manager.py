import asyncio
from typing import Any, Dict, Optional

from core.config import Config
from core.logger import logger

from .fetch_service import FetchService


class FetchManager:
    def __init__(self, config: Config):
        self.config = config
        self.fetch_service = FetchService()
        self.semaphore = asyncio.Semaphore(config.global_config.max_concurrency)

    async def request(
        self, method: str, url: str, proxy: Optional[str] = None, **kwargs
    ) -> Dict[str, Any]:
        """
        使用信号量控制并发的请求方法
        """
        async with self.semaphore:
            for _ in range(self.config.global_config.retry_times):
                try:
                    response = await self.fetch_service.request(
                        method=method, url=url, proxy=proxy, timeout=10, **kwargs
                    )

                    if "error" not in response:
                        return response

                except asyncio.TimeoutError:
                    logger.warning(f"请求超时,正在重试: {url}")
                    continue

            logger.error(f"达到最大重试次数: {url}")
            return {"error": "Max retries exceeded"}
