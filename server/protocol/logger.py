## Group Name & Members
# - Group Name: Group Project 8
# - Anthonan Hettige Achala Tharaka Dias (a1933508)
# - Sanjida Amrin (a1934493)
# - Zahin Rydha (a1938252)

import logging

def get_logger(name="chat_server"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Prevent adding handlers multiple times
    if not logger.handlers:
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s', "%Y-%m-%d %H:%M:%S"
        )

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File handler
        file_handler = logging.FileHandler("server.log")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
