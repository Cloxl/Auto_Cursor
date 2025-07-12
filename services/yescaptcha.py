import time
from dataclasses import dataclass
from typing import Dict, Optional

import requests
from core.logger import logger


@dataclass
class TurnstileConfig:
    client_key: str
    website_url: str
    website_key: str
    use_cn_server: bool = True


class YesCaptcha:
    API_URL_GLOBAL = "https://api.yescaptcha.com"
    API_URL_CN = "https://cn.yescaptcha.com"

    def __init__(self, config: TurnstileConfig):
        self.config = config
        self.base_url = self.API_URL_CN if config.use_cn_server else self.API_URL_GLOBAL
        logger.debug(f"YesCaptcha 初始化 - 使用{'国内' if config.use_cn_server else '国际'}服务器")

    def create_task(self, task_type: str = "TurnstileTaskProxyless") -> Dict:
        """
        Create a new Turnstile solving task
        
        Args:
            task_type: Either "TurnstileTaskProxyless" (25 points) or "TurnstileTaskProxylessM1" (30 points)
        
        Returns:
            Dict containing task ID if successful
        """
        url = f"{self.base_url}/createTask"
        # logger.debug(f"创建验证任务 - 类型: {task_type}")

        payload = {
            "clientKey": self.config.client_key,
            "task": {
                "type": task_type,
                "websiteURL": self.config.website_url,
                "websiteKey": self.config.website_key
            }
        }

        response = requests.post(url, json=payload)
        result = response.json()
        
        if result.get("errorId", 1) != 0:
            logger.error(f"创建任务失败: {result.get('errorDescription')}")
        # else:
            # logger.debug(f"创建任务成功 - TaskID: {result.get('taskId')}")
            
        return result

    def get_task_result(self, task_id: str) -> Dict:
        """
        Get the result of a task
        
        Args:
            task_id: Task ID from create_task
            
        Returns:
            Dict containing task result if successful
        """
        url = f"{self.base_url}/getTaskResult"
        # logger.debug(f"获取任务结果 - TaskID: {task_id}")

        payload = {
            "clientKey": self.config.client_key,
            "taskId": task_id
        }

        response = requests.post(url, json=payload)
        result = response.json()
        
        if result.get("errorId", 1) != 0:
            logger.error(f"获取结果失败: {result.get('errorDescription')}")
        # elif result.get("status") == "ready":
        #     logger.debug("成功获取到结果")
            
        return result

    def solve_turnstile(self, max_attempts: int = 60) -> Optional[str]:
        """
        Complete turnstile solving process
        
        Args:
            max_attempts: Maximum number of attempts to get result
            
        Returns:
            Token string if successful, None otherwise
        """
        # 创建任务
        create_result = self.create_task()
        if create_result.get("errorId", 1) != 0:
            return None
            
        task_id = create_result.get("taskId")
        if not task_id:
            return None

        # 轮询获取结果
        for _ in range(max_attempts):
            result = self.get_task_result(task_id)
            
            if result.get("status") == "ready":
                return result.get("solution", {}).get("token")
                
            if result.get("errorId", 1) != 0:
                return None
                
            time.sleep(1)
            
        return None
