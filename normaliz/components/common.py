import os,logging.config, sys, json, yaml


# load config from yaml file
with open(os.environ['CONFIG_FILE']) as f:
  cfg = yaml.safe_load(f)


class CallLogger(object):
  @classmethod
  def logger(cls):

    logging.config.dictConfig(cfg['logger'])
    return logging.getLogger(os.environ.get('HOSTNAME'))

logger = CallLogger.logger()