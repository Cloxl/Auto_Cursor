import asyncio
from typing import List, Tuple

import aiohttp

from core.config import Config
from core.exceptions import TokenGenerationError
from core.logger import logger
from services.capsolver import Capsolver
from services.yescaptcha import TurnstileConfig, YesCaptcha


class TokenPool:
    def __init__(self, config: Config):
        self.config = config

        # 设置provider属性
        self.provider = config.captcha_config.provider

        if self.provider == "capsolver":
            self.solver = Capsolver(
                api_key=config.captcha_config.capsolver.api_key,
                website_url=config.captcha_config.capsolver.website_url,
                website_key=config.captcha_config.capsolver.website_key,
            )
        elif self.provider == "yescaptcha":
            self.turnstile_config = TurnstileConfig(
                client_key=config.captcha_config.yescaptcha.client_key,
                website_url=config.captcha_config.yescaptcha.website_url,
                website_key=config.captcha_config.yescaptcha.website_key,
                use_cn_server=config.captcha_config.yescaptcha.use_cn_server,
            )
            self.solver = YesCaptcha(self.turnstile_config)
        elif self.provider == "custom":
            pass
        else:
            logger.warning(f"未知的provider类型: {self.provider}, 默认使用capsolver")
            self.provider = "capsolver"
            self.solver = Capsolver(
                api_key=config.captcha_config.capsolver.api_key,
                website_url=config.captcha_config.capsolver.website_url,
                website_key=config.captcha_config.capsolver.website_key,
            )

    async def _get_tokens_from_api(self, count: int) -> List[str]:
        """从自定义API获取tokens

        Args:
            count: 需要的token数量

        Returns:
            List[str]: token列表
        """
        try:
            custom_config = self.config.captcha_config.custom
            if not custom_config.api_url:
                raise TokenGenerationError("自定义token API URL未配置")

            # 构建请求URL
            url = custom_config.api_url
            params = {
                custom_config.limit_param: count,
                custom_config.status_param: custom_config.status_value,
            }

            # 准备请求头
            headers = {"Accept": "application/json", "User-Agent": "CursorRegister/1.0"}
            if custom_config.headers:
                headers.update(custom_config.headers)

            logger.debug(f"正在从API获取 {count} 个token: {url}")

            # 创建禁用SSL验证的connector
            conn = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=conn) as session:
                async with session.get(url, params=params, headers=headers) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise TokenGenerationError(
                            f"API请求失败，状态码: {response.status}, 错误: {error_text}"
                        )

                    data = await response.json()

                    # 检查返回数据格式
                    if custom_config.token_key not in data:
                        raise TokenGenerationError(
                            f"API返回格式错误，未找到tokens字段: {data}"
                        )

                    tokens = data[custom_config.token_key]
                    if not tokens or not isinstance(tokens, list):
                        raise TokenGenerationError(f"API返回的tokens格式错误: {tokens}")

                    return tokens
        except Exception as e:
            logger.error(f"从自定义API获取token失败: {str(e)}")
            raise TokenGenerationError(f"从自定义API获取token失败: {str(e)}")

    async def _get_token(self) -> str:
        """获取单个token"""
        try:
            if self.provider == "custom":
                # 从自定义API获取token (每次只获取一个)
                tokens = await self._get_tokens_from_api(1)
                if not tokens:
                    raise TokenGenerationError("Failed to get token from custom API")
                return tokens[0]
            elif isinstance(self.solver, Capsolver):
                # Capsolver 是异步的,直接调用
                token = await self.solver.solve_turnstile()
            else:
                # YesCaptcha 是同步的,需要转换
                token = await asyncio.to_thread(self.solver.solve_turnstile)

            if not token:
                raise TokenGenerationError("Failed to get token")
            return token

        except Exception as e:
            logger.error(f"获取 token 失败: {str(e)}")
            raise TokenGenerationError(f"Failed to get token: {str(e)}")

    async def get_token_pair(self) -> Tuple[str, str]:
        """获取一对token"""
        token1 = await self._get_token()
        token2 = await self._get_token()
        return token1, token2

    async def batch_generate(self, num: int) -> List[Tuple[str, str]]:
        """批量生成token对

        Args:
            num: 需要的token对数量

        Returns:
            List[Tuple[str, str]]: token对列表，每个元素是(token1, token2)
        """
        logger.info(f"开始批量生成 {num} 对 token，provider: {self.provider}")

        # 使用自定义API批量获取token
        if self.provider == "custom":
            try:
                # 一次性从API获取所需数量的token（每对需要两个，所以是num*2）
                tokens = await self._get_tokens_from_api(num * 2)

                valid_tokens = [token for token in tokens if len(token) >= 100]

                if len(valid_tokens) < num * 2:
                    logger.warning(
                        f"从API获取的有效token数量不足: 需要{num * 2}个, 实际获取{len(valid_tokens)}个"
                    )

                # 将token分组为对
                token_pairs = []
                for i in range(0, len(valid_tokens), 2):
                    if i + 1 < len(valid_tokens):
                        pair = (valid_tokens[i], valid_tokens[i + 1])
                        token_pairs.append(pair)
                    else:
                        break

                logger.success(f"成功从API获取 {len(token_pairs)} 对 token")
                return token_pairs
            except Exception as e:
                logger.error(f"从API批量获取token失败: {str(e)}")
                return []

        # 原有的token生成逻辑
        # 创建所有token获取任务
        tasks = []
        for _ in range(num * 2):  # 每对需要两个token
            tasks.append(self._get_token())

        # 并发执行所有任务
        try:
            tokens = await asyncio.gather(*tasks, return_exceptions=True)

            valid_tokens = [token for token in tokens if len(token) >= 100]

            # 将token分组为对
            token_pairs = []
            for i in range(0, len(valid_tokens), 2):
                if i + 1 < len(valid_tokens):
                    pair = (valid_tokens[i], valid_tokens[i + 1])
                    token_pairs.append(pair)
                else:
                    break

            logger.success(f"成功生成 {len(token_pairs)} 对 token")
            return token_pairs

        except Exception as e:
            logger.error(f"批量生成 token 失败: {str(e)}")
            return []
