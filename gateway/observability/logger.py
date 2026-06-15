import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
        }
        # Nếu có chèn thêm dữ liệu phụ (extra) thì gộp chung vào JSON
        if hasattr(record, "extra_info"):
            log_record.update(record.extra_info)
        return json.dumps(log_record)

def setup_logger():
    logger = logging.getLogger("gateway")
    logger.setLevel(logging.INFO)
    logger.propagate = False # Tránh in log lặp lại 2 lần
    
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JSONFormatter())
        logger.addHandler(console_handler)
        
    return logger

gateway_logger = setup_logger()
