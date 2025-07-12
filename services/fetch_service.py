from typing import Any, Dict, Optional, Union

from curl_cffi.requests import AsyncSession
from core.logger import logger


class FetchService:
    def __init__(self):
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd"
        }

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[Union[Dict, str]] = None,
        json: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        proxy: Optional[str] = None,
        impersonate: str = "chrome124",
        **kwargs
    ) -> Dict[str, Any]:
        """
        通用请求方法
        
        Args:
            method: 请求方法 (GET, POST 等)
            url: 请求URL
            headers: 请求头
            params: URL参数
            data: 表单数据
            json: JSON数据
            cookies: Cookie
            proxy: 代理地址
            impersonate: 浏览器仿真类型
            **kwargs: 其他curl_cffi支持的参数
            
        Returns:
            Dict 包含响应信息
        """
        # 合并默认headers
        request_headers = self.default_headers.copy()
        if headers:
            request_headers.update(headers)

        try:
            async with AsyncSession(impersonate=impersonate) as session:
                response = await session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    params=params,
                    data=data,
                    json=json,
                    cookies=cookies,
                    proxies={'http': proxy, 'https': proxy} if proxy else None,
                    verify=False,
                    quote=False,
                    stream=True,
                    **kwargs
                )
                
                return {
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'cookies': dict(response.cookies),
                    'body': await response.acontent(),
                    'raw_response': response
                }
                
        except Exception as e:
            logger.error(f"请求失败: {str(e)}")
            return {'error': str(e)}
