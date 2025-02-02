import logging

def setup_logger():
    """ Set up and configure logging """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # Set up handler and formatter later
    return logger

# Initialize logger
logger = setup_logger()