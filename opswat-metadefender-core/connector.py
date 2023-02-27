""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('opswat-metadefender-core')


class Opswat(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation: {0}'.format(operation))
        try:
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.error('{0}'.format(err))
            raise ConnectorError('{0}'.format(err))

    def check_health(self, config):
        return _check_health(config)

