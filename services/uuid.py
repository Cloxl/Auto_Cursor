import random
import time


class ULID:
    def __init__(self):
        # 定义字符集，使用Crockford's Base32字符集
        self.encoding = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    
    def generate(self) -> str:
        # 获取当前时间戳（毫秒）
        timestamp = int(time.time() * 1000)
        
        # 生成随机数部分
        randomness = random.getrandbits(80)  # 80位随机数
        
        # 转换时间戳为base32字符串（10个字符）
        time_chars = []
        for _ in range(10):
            timestamp, mod = divmod(timestamp, 32)
            time_chars.append(self.encoding[mod])
        time_chars.reverse()
        
        # 转换随机数为base32字符串（16个字符）
        random_chars = []
        for _ in range(16):
            randomness, mod = divmod(randomness, 32)
            random_chars.append(self.encoding[mod])
        random_chars.reverse()
        
        # 组合最终结果
        return ''.join(time_chars + random_chars)
