import logging

from .graph import MailGraph

__all__ = ["MailGraph"]
from mailtrace.config import Config, load_config

logger = logging.getLogger("mailtrace")


def init_logger(config: Config):
    if logger.hasHandlers():
        return
    logger.propagate = False
    log_level = config.log_level
    logger.setLevel(log_level)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    opensearch_logger = logging.getLogger("opensearch")
    opensearch_logger.propagate = False
    opensearch_logger.setLevel(log_level)
    if not opensearch_logger.hasHandlers():
        opensearch_stream_handler = logging.StreamHandler()
        opensearch_stream_handler.setFormatter(formatter)
        opensearch_logger.addHandler(opensearch_stream_handler)


config = load_config()
init_logger(config)
