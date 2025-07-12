from typing import List

from core.config import Config
from core.exceptions import ProxyFetchError
from core.logger import logger

from .fetch_manager import FetchManager


class ProxyPool:
    def __init__(self, config: Config, fetch_manager: FetchManager):
        self.config = config
        self.fetch_manager = fetch_manager

    async def batch_get(self, num: int) -> List[str]:
        """获取num个代理"""
        # 检查配置的API URL
        if not self.config.proxy_config.api_url:
            # 如果没有配置代理API，则使用直接连接（无代理）
            logger.warning("未配置代理API URL，将使用直接连接")
            return [""] * num

        # 如果配置了使用本地代理
        if self.config.proxy_config.use_local_proxy:
            proxy = self.config.proxy_config.api_url
            logger.info(f"使用本地代理: {proxy}")
            return [proxy] * num

        # 从API获取代理
        try:
            logger.info(f"从API获取代理: {self.config.proxy_config.api_url}")
            response = await self.fetch_manager.request(
                "GET",
                self.config.proxy_config.api_url.format(num),
                proxy="http://127.0.0.1:7890",
            )

            if "error" in response:
                raise ProxyFetchError(response["error"])

            proxies = self._parse_proxies(response["body"])
            return proxies[:num]

        except Exception as e:
            logger.error(f"获取代理失败: {str(e)}")
            raise ProxyFetchError(f"Failed to fetch proxies: {str(e)}")

    def _parse_proxies(self, response_body: str) -> List[str]:
        """解析代理API返回的数据"""
        proxies = []
        for line in response_body.decode().splitlines():
            line = line.strip()
            if line:
                if not line.startswith("http"):
                    line = f"http://{line}"
                proxies.append(line)
        return proxies
