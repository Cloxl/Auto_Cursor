import asyncio
import aiosqlite
import time
import threading
import traceback
from typing import Any, List, Optional, Dict
from contextlib import asynccontextmanager
from core.logger import logger

from core.config import Config


class DatabaseManager:
    def __init__(self, config: Config):
        self.db_path = config.database_config.path
        self._pool_size = config.database_config.pool_size
        self._pool = []
        self._pool_lock = asyncio.Lock()
        self._active_connections = {}  # 跟踪活跃连接
        self._connection_id = 0  # 连接ID计数器
        
    async def initialize(self):
        """初始化数据库"""
        async with self.get_connection("初始化数据库") as conn:
            # 创建邮箱账号表
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS email_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    in_use BOOLEAN DEFAULT 0,
                    cursor_password TEXT,
                    cursor_cookie TEXT,
                    cursor_token TEXT,
                    sold BOOLEAN DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    verification_sent BOOLEAN DEFAULT 0,
                    verification_sent_time TIMESTAMP,
                    verification_attempts INTEGER DEFAULT 0,
                    verification_code TEXT,
                    registration_complete BOOLEAN DEFAULT 0,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            await conn.commit()
            
            # 创建数据库连接日志表
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS db_connection_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_id INTEGER NOT NULL,
                    operation TEXT NOT NULL,
                    caller TEXT NOT NULL,
                    thread_id INTEGER NOT NULL,
                    task_id TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    stack_trace TEXT
                )
            ''')
            await conn.commit()
    
    async def cleanup(self):
        """清理资源"""
        for conn_id, conn_info in list(self._active_connections.items()):
            conn = conn_info["connection"]
            logger.warning(f"关闭未释放的连接 {conn_id}: {conn_info['caller']}")
            await conn.close()
        
        self._active_connections = {}
        
        for conn in self._pool:
            await conn.close()
        self._pool = []
    
    @asynccontextmanager
    async def get_connection(self, caller="未知"):
        """
        获取数据库连接，带有重试机制和跟踪功能
        
        Args:
            caller: 调用者标识，用于跟踪连接使用
        """
        max_retries = 5
        retry_delay = 0.2  # 初始延迟200毫秒
        conn = None
        conn_id = None
        
        # 获取当前线程和任务信息
        thread_id = threading.get_ident()
        task = asyncio.current_task()
        task_id = id(task) if task else 0
        
        # 记录连接请求
        start_time = time.time()
        stack_trace = "".join(traceback.format_stack())
        
        for attempt in range(max_retries):
            try:
                async with self._pool_lock:
                    self._connection_id += 1
                    conn_id = self._connection_id
                    
                    if not self._pool:
                        conn = await aiosqlite.connect(
                            self.db_path, 
                            timeout=20.0  # 增加超时时间到20秒
                        )
                        # 启用WAL模式，提高并发性能
                        await conn.execute("PRAGMA journal_mode=WAL")
                        # 设置更宽松的锁定模式
                        await conn.execute("PRAGMA busy_timeout=10000")  # 10秒超时
                    else:
                        conn = self._pool.pop()
                    
                    # 记录活跃连接
                    self._active_connections[conn_id] = {
                        "connection": conn,
                        "caller": caller,
                        "thread_id": thread_id,
                        "task_id": task_id,
                        "start_time": start_time,
                        "stack_trace": stack_trace
                    }
                    
                    # 记录连接日志
                    await self._log_connection(conn, conn_id, "获取连接", caller, thread_id, task_id, start_time)
                
                # 成功获取连接
                break
            except Exception as e:
                if attempt < max_retries - 1:
                    # 指数退避重试
                    wait_time = retry_delay * (2 ** attempt)
                    logger.warning(f"数据库连接失败，{wait_time}秒后重试: {str(e)}")
                    await asyncio.sleep(wait_time)
                else:
                    # 最后一次尝试失败，记录错误并抛出异常
                    if conn_id:
                        await self._log_connection_error(conn_id, "获取连接失败", caller, thread_id, task_id, start_time, str(e), stack_trace)
                    raise Exception(f"无法获取数据库连接: {str(e)}")
                
        try:
            yield conn
        finally:
            try:
                # 记录连接释放
                end_time = time.time()
                await self._log_connection(conn, conn_id, "释放连接", caller, thread_id, task_id, start_time, end_time)
                
                # 从活跃连接中移除
                if conn_id in self._active_connections:
                    del self._active_connections[conn_id]
                
                if len(self._pool) < self._pool_size:
                    self._pool.append(conn)
                else:
                    await conn.close()
            except Exception as e:
                logger.error(f"关闭数据库连接时出错: {str(e)}")
    
    async def _log_connection(self, conn, conn_id, operation, caller, thread_id, task_id, start_time, end_time=None):
        """记录连接操作到数据库"""
        try:
            status = "完成" if end_time else "进行中"
            
            # 直接使用连接执行，避免递归调用get_connection
            await conn.execute(
                """
                INSERT INTO db_connection_logs 
                (connection_id, operation, caller, thread_id, task_id, start_time, end_time, status, error_message, stack_trace)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (conn_id, operation, caller, thread_id, str(task_id), start_time, end_time, status)
            )
            await conn.commit()
        except Exception as e:
            logger.error(f"记录连接日志失败: {str(e)}")
    
    async def _log_connection_error(self, conn_id, operation, caller, thread_id, task_id, start_time, error_message, stack_trace):
        """记录连接错误到数据库"""
        try:
            # 创建一个新连接来记录错误
            async with aiosqlite.connect(self.db_path, timeout=5.0) as conn:
                await conn.execute(
                    """
                    INSERT INTO db_connection_logs 
                    (connection_id, operation, caller, thread_id, task_id, start_time, end_time, status, error_message, stack_trace)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (conn_id, operation, caller, thread_id, str(task_id), start_time, time.time(), "失败", error_message, stack_trace)
                )
                await conn.commit()
        except Exception as e:
            logger.error(f"记录连接错误日志失败: {str(e)}")
    
    async def get_active_connections(self) -> List[Dict]:
        """获取当前活跃的数据库连接信息"""
        result = []
        
        for conn_id, conn_info in self._active_connections.items():
            duration = time.time() - conn_info["start_time"]
            result.append({
                "connection_id": conn_id,
                "caller": conn_info["caller"],
                "thread_id": conn_info["thread_id"],
                "task_id": conn_info["task_id"],
                "duration": f"{duration:.2f}秒",
                "stack_trace": conn_info["stack_trace"]
            })
            
        return result
    
    async def get_connection_logs(self, limit=50) -> List[Dict]:
        """获取最近的数据库连接日志"""
        try:
            async with self.get_connection("获取连接日志") as conn:
                cursor = await conn.execute(
                    """
                    SELECT * FROM db_connection_logs 
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,)
                )
                rows = await cursor.fetchall()
                
                # 获取列名
                columns = [desc[0] for desc in cursor.description]
                
                # 转换为字典列表
                result = []
                for row in rows:
                    result.append(dict(zip(columns, row)))
                    
                return result
        except Exception as e:
            logger.error(f"获取连接日志失败: {str(e)}")
            return []
    
    async def execute(self, query: str, params: tuple = (), retries: int = 3, caller: str = "未知") -> Any:
        """执行SQL语句，带有重试机制"""
        last_error = None
        retry_delay = 0.2  # 初始延迟200毫秒
        
        start_time = time.time()
        
        for attempt in range(retries):
            try:
                async with self.get_connection(caller) as conn:
                    cursor = await conn.execute(query, params)
                    await conn.commit()
                    
                    # 记录SQL操作成功
                    end_time = time.time()
                    
                    return cursor.lastrowid
            except Exception as e:
                last_error = e
                if "database is locked" in str(e) and attempt < retries - 1:
                    # 指数退避重试
                    wait_time = retry_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                else:
                    break
        
        # 记录SQL操作最终失败
        end_time = time.time()
        
        raise Exception(f"执行SQL失败: {str(last_error)}")
                
    async def fetch_one(self, query: str, params: tuple = (), retries: int = 3, caller: str = "未知") -> Optional[tuple]:
        """查询单条记录，带有重试机制"""
        last_error = None
        retry_delay = 0.2  # 初始延迟200毫秒
        
        for attempt in range(retries):
            try:
                async with self.get_connection(caller) as conn:
                    cursor = await conn.execute(query, params)
                    return await cursor.fetchone()
            except Exception as e:
                last_error = e
                if "database is locked" in str(e) and attempt < retries - 1:
                    # 指数退避重试
                    wait_time = retry_delay * (2 ** attempt)
                    logger.warning(f"数据库锁定，{wait_time}秒后重试: {str(e)}")
                    await asyncio.sleep(wait_time)
                else:
                    # 其他错误或最后一次尝试失败，抛出异常
                    break
        
        raise Exception(f"查询SQL失败: {str(last_error)}")
            
    async def fetch_all(self, query: str, params: tuple = (), retries: int = 3, caller: str = "未知") -> List[tuple]:
        """查询多条记录，带有重试机制"""
        last_error = None
        retry_delay = 0.2  # 初始延迟200毫秒
        
        for attempt in range(retries):
            try:
                async with self.get_connection(caller) as conn:
                    cursor = await conn.execute(query, params)
                    return await cursor.fetchall()
            except Exception as e:
                last_error = e
                if "database is locked" in str(e) and attempt < retries - 1:
                    # 指数退避重试
                    wait_time = retry_delay * (2 ** attempt)
                    logger.warning(f"数据库锁定，{wait_time}秒后重试: {str(e)}")
                    await asyncio.sleep(wait_time)
                else:
                    # 其他错误或最后一次尝试失败，抛出异常
                    break
        
        raise Exception(f"查询SQL失败: {str(last_error)}")
            
    async def get_pending_accounts(self, batch_size: int) -> List[dict]:
        """获取待发送验证码的账号"""
        query = """
            SELECT id, email, password, client_id, refresh_token
            FROM email_accounts
            WHERE verification_sent = 0 AND status = 'pending'
            LIMIT ?
        """
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(query, (batch_size,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
            
    async def update_verification_sent(self, account_id: int, success: bool, error_message: str = None):
        """更新验证码发送状态"""
        if success:
            query = """
                UPDATE email_accounts
                SET verification_sent = 1, 
                    verification_sent_time = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """
            params = (account_id,)
        else:
            query = """
                UPDATE email_accounts
                SET error_message = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """
            params = (error_message, account_id)
            
        await self.execute(query, params)

    async def check_database_locks(self) -> dict:
        """
        检查数据库锁状态和连接信息
        
        Returns:
            dict: 包含锁状态和连接信息的字典
        """
        result = {
            "locks": [],
            "connections": [],
            "busy": False
        }
        
        try:
            # 尝试建立一个新连接来检查锁状态
            conn = await aiosqlite.connect(self.db_path, timeout=1.0)
            
            # 检查数据库锁状态
            cursor = await conn.execute("PRAGMA lock_status")
            locks = await cursor.fetchall()
            result["locks"] = [{"type": lock[0], "status": lock[1]} for lock in locks]
            
            # 检查活跃连接
            cursor = await conn.execute("PRAGMA database_list")
            databases = await cursor.fetchall()
            result["connections"] = [{"seq": db[0], "name": db[1], "file": db[2]} for db in databases]
            
            # 关闭连接
            await conn.close()
            
        except aiosqlite.OperationalError as e:
            if "database is locked" in str(e):
                result["busy"] = True
                logger.warning(f"数据库已锁定，无法获取锁状态: {str(e)}")
            else:
                logger.error(f"检查数据库锁状态时出错: {str(e)}")
        except Exception as e:
            logger.error(f"检查数据库锁状态时出现未知错误: {str(e)}")
            
        return result 

    async def diagnose_lock_issues(self) -> Dict:
        """
        诊断数据库锁定问题
        
        Returns:
            Dict: 包含诊断信息的字典
        """
        result = {
            "lock_status": await self.check_database_locks(),
            "active_connections": await self.get_active_connections(),
            "recent_logs": await self.get_connection_logs(10),
            "diagnosis": [],
            "suggestions": []
        }
        
        # 分析活跃连接
        if len(result["active_connections"]) > 5:
            result["diagnosis"].append(f"当前有{len(result['active_connections'])}个活跃连接，可能导致竞争")
            result["suggestions"].append("减少并发数据库操作，或增加连接池大小")
        
        # 检查长时间运行的连接
        long_running = [conn for conn in result["active_connections"] 
                        if float(conn["duration"].replace("秒", "")) > 5.0]
        if long_running:
            result["diagnosis"].append(f"发现{len(long_running)}个长时间运行的连接（>5秒）")
            for conn in long_running:
                result["diagnosis"].append(f"连接ID {conn['connection_id']} ({conn['caller']}) 运行了 {conn['duration']}")
            result["suggestions"].append("检查长时间运行的查询，可能存在性能问题")
        
        # 检查是否有锁
        if result["lock_status"]["busy"]:
            result["diagnosis"].append("数据库当前处于锁定状态")
            result["suggestions"].append("等待当前事务完成，或增加超时时间")
        
        # 如果没有发现明显问题
        if not result["diagnosis"]:
            result["diagnosis"].append("未发现明显的锁定问题")
            result["suggestions"].append("考虑使用WAL模式和更长的超时时间")
        
        return result 