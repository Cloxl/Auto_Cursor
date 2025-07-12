import argparse
import os
import sqlite3
from datetime import datetime

import pandas as pd

from core.config import Config
from core.logger import logger


def export_database_to_excel_and_txt(config, start_index=0, limit=None):
    """
    从数据库中导出数据到Excel和TXT文件
    字段包括：email, password, cursor_password, cursor_cookie, cursor_token

    参数:
        config: 配置对象，包含数据库路径等信息
        start_index: 开始的索引位置，默认为0
        limit: 导出的记录数量，默认为None（全部）
    """
    # 连接到数据库
    try:
        # 从配置中获取数据库路径
        db_path = config.database_config.path
        logger.info(f"使用数据库: {db_path}")

        # 确保数据库目录存在
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"创建数据库目录: {db_dir}")

        # 连接数据库
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 获取总记录数
        cursor.execute(
            "SELECT COUNT(*) FROM email_accounts WHERE cursor_cookie IS NOT NULL"
        )
        total_records = cursor.fetchone()[0]

        logger.info(f"数据库中共有 {total_records} 条记录(cursor_cookie不为空)")

        # 使用参数值或默认值
        if start_index is None:
            start_index = 0

        logger.info(f"使用开始索引: {start_index}")

        # 如果未提供导出数量，默认导出全部
        if limit is None:
            logger.info(f"导出记录数量: 全部 ({total_records})")
        else:
            logger.info(f"导出记录数量: {limit}")

        # 构建SQL查询
        sql = """
        SELECT email, password, cursor_password, cursor_cookie, cursor_token
        FROM email_accounts
        WHERE cursor_cookie IS NOT NULL 
        AND id >= ?
        LIMIT ?
        """

        # 执行查询
        cursor.execute(sql, (start_index, limit if limit is not None else -1))
        records = cursor.fetchall()

        if not records:
            logger.warning("没有找到符合条件的记录")
            return

        # 创建DataFrame
        df = pd.DataFrame(
            records,
            columns=["邮箱", "邮箱密码", "cursor密码", "cursor_cookie", "cursor_token"],
        )

        # 创建exports目录（如果不存在）
        export_dir = "exports"
        if not os.path.exists(export_dir):
            os.makedirs(export_dir, exist_ok=True)
            logger.info(f"创建导出目录: {export_dir}")

        # 生成文件名(带时间戳和记录数量)
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        record_count = len(records)
        excel_filename = os.path.join(export_dir, f"{timestamp}-{record_count}.csv")
        txt_filename = os.path.join(export_dir, f"{timestamp}-{record_count}.txt")

        # 导出为CSV
        df.to_csv(excel_filename, index=False)

        # 导出为TXT
        with open(txt_filename, "w", encoding="utf-8") as f:
            for record in records:
                line = "----".join(
                    [str(item) if item is not None else "" for item in record]
                )
                f.write(line + "\n")

        logger.success(f"成功导出 {len(records)} 条记录")
        logger.info(f"CSV文件: {os.path.abspath(excel_filename)}")
        logger.info(f"TXT文件: {os.path.abspath(txt_filename)}")

    except Exception as e:
        logger.error(f"导出数据时发生错误: {str(e)}")
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description="从数据库导出Cursor账户数据")
    parser.add_argument("--start", type=int, help="开始索引，默认为0")
    parser.add_argument("--limit", type=int, help="导出记录数量，默认为全部")

    # 解析命令行参数
    args = parser.parse_args()

    # 加载配置
    config = Config.from_yaml()

    # 调用导出函数
    export_database_to_excel_and_txt(config, args.start, args.limit)
