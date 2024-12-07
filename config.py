import loguru
import os
loguru.logger.add("log/DEBUG.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="DEBUG")
loguru.logger.add("log/INFO.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="INFO")
loguru.logger.add("log/ERROR.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="ERROR")
loguru.logger.add("log/WARNING.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="WARNING")

# SOLC_BIN_PATH = "/home/wanthinnn/Documents/NT521/Project/CrossFuzz/myenv/bin/solc"  # set to your solc path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Thư mục chứa script Python
# print(BASE_DIR)
SOLC_BIN_PATH = os.path.join(BASE_DIR, "myenv/bin/solc")
# print(SOLC_BIN_PATH)
################


def get_logger() -> loguru.logger:
    return loguru.logger
