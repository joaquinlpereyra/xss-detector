import logging
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.basicConfig(filename='logs/logs.log', level=logging.DEBUG,
                    format='[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
                    datefmt='%H:%M:%S')

console_logger = logging.StreamHandler()
console_logger.setLevel(logging.ERROR)
console_format = logging.Formatter('%(levelname)-s: %(message)s')
console_logger.setFormatter(console_format)
logging.getLogger('').addHandler(console_logger)
logger = logging.getLogger('')
