"""
main.py
====================================
The core module of dynflags
"""
from __future__ import print_function

from botocore.exceptions import ClientError
from datetime import datetime
from six import string_types

import boto3
import logging

from .config import DynFlagsConfig
from .exceptions import *

DEFAULT_TABLE_SPEC = {"BillingMode": 'PAY_PER_REQUEST'}


def write_only(func):
    def block_read_only(self, *args, **kwargs):
        if self.config.read_only:
            raise ReadOnlyException()
        return func(self, *args, **kwargs)

    return block_read_only


class DynFlagManager:
    def __init__(self, config={}, cache=None, logger=None):
        self.config = DynFlagsConfig(config)
        self._dynamo = None
        self.cached_table_obj = None
        self.cache = cache
        self.logger = logger or logging.getLogger(__name__)

    def _initialize_table(self):
        # create the table
        self.logger.debug('Creating DynamoDB Table: %s, %s' %
                           (self.config.table_name, self.config.table_config))
        table = self.dynamo.create_table(TableName=self.config.table_name,
                                         KeySchema=[{
                                             "AttributeName": "arguments",
                                             "KeyType": "HASH"
                                         }],
                                         AttributeDefinitions=[{
                                             "AttributeName":
                                             "arguments",
                                             "AttributeType":
                                             "S"
                                         }],
                                         **self.config.table_config)
        table.meta.client.get_waiter('table_exists').wait(
            TableName=self.config.table_name)
        self.logger.debug('DynamoDB Table Created')

    def _gen_dynamo_key_from_key(self, key):
        return {"arguments": key}

    def _validate_arguments(self, arguments):
        if not all(isinstance(x, string_types) for x in arguments.keys()):
            raise InvalidArgumentKeyTypeException(
                'Argument keys must be strings')
        if not all(isinstance(x, string_types) for x in arguments.values()):
            raise InvalidArgumentValueTypeException(
                'Argument values must be strings')

    def _validate_flag_names(self, flags):
        if not all(isinstance(x, string_types) for x in flags):
            raise InvalidFlagNameTypeException('Flag names must be string')

    def _gen_key_from_args(self, arguments):
        if not arguments:
            return self.config.default_key
        self._validate_arguments(arguments)
        arglist = list(arguments.items())
        arglist.sort(key=lambda x: x[0])
        key_fragments = ("%s=%s" % (x, str(y)) for x, y in arglist)
        key = ';'.join(key_fragments)
        self.logger.debug('Generated key from args: %s, %s' %
                           (arguments, key))
        return key

    def _gen_args_from_key(self, key):
        args = {}
        for frag in key.split(';'):
            k, v = frag.split("=")
            args[k] = v
        return args

    def _query_dynamodb_for_flags_for_key(self, key):
        self.logger.debug('Querying DynamoDB for key: %s' %
                           self._gen_dynamo_key_from_key(key))
        item = self.table.get_item(Key=self._gen_dynamo_key_from_key(key),
                                   ConsistentRead=self.config.consistent_reads)
        flag_states = item.get('Item', {}).get('flag_states', {})
        self.logger.debug('Found flag states for key: %s, %s' %
                           (key, flag_states))
        return flag_states

    def get_flags_for_key(self, key, usecache=True):
        if usecache and self.cache:
            self.logger.debug('Checking cache for key: %s' % key)
            cached_flags = self.cache.get(key)
            if cached_flags:
                self.logger.debug('Returning cached flags for key: %s, %s' %
                                   (key, cached_flags))
                return cached_flags
        flags = self._query_dynamodb_for_flags_for_key(key)
        if usecache and self.cache:
            self.logger.debug('Setting cache for key: %s, %s' % (key, flags))
            self.cache.set(key, flags)
        return flags

    def get_flags_for_args(self, arguments, usecache=True):
        key = self._gen_key_from_args(arguments)
        return self.get_flags_for_key(key, usecache)

    @property
    def dynamo(self):
        if not self._dynamo:
            self._dynamo = boto3.resource('dynamodb', **self.config.boto_config)
        return self._dynamo

    @property
    def table(self):
        if self.cached_table_obj:
            self.logger.debug('Returning cached table object')
            return self.cached_table_obj
        self.logger.debug('Table object not cached')
        self.cached_table_obj = self.dynamo.Table(self.config.table_name)
        try:
            self.cached_table_obj.creation_date_time
        except self.dynamo.meta.client.exceptions.ResourceNotFoundException as exc:
            self.logger.debug('Table does not exist')
            if self.config.autocreate_table:
                self._initialize_table()
            else:
                raise exc
        return self.cached_table_obj

    def is_active(self, *args, **kwargs):
        if self.config.robust:
            try:
                return self._is_active(*args, **kwargs)
            except Exception as exc:
                self.logger.error(str(exc))
                return False
        else:
            return self._is_active(*args, **kwargs)

    def _is_active(self, flag_name, arguments={}, usecache=True):
        self._validate_flag_names([flag_name])
        flag_states = self.get_flags_for_args(arguments, usecache)
        return flag_states.get(flag_name, False)

    @write_only
    def _gen_update_expression(self, flag_states):
        """
        Handles the complexity of updating states where True and False need stored, but None means deletion
        """
        attr_values = {':%s' % k:v for k,v in flag_states.items() if v in (True, False)}
        attr_values[':_version_inc'] = 1
        attr_values[':_updated_time'] = datetime.utcnow().isoformat()
        SETS = ['last_update_time = :_updated_time']
        DELS = []
        for flag_name, flag_state in flag_states.items():
            if flag_state == None:
                DELS.append('flag_states.%s' % flag_name)
            elif flag_state in (True, False):
                SETS.append('flag_states.%s = :%s' % (flag_name, flag_name))
            else:
                raise InvalidFlagState('Invalid flag state for flag %s: %s' % (flag_name, repr(flag_state)))
        components = ['ADD version :_version_inc']
        if SETS: components.append('SET %s' % ', '.join(SETS))
        if DELS: components.append('REMOVE %s' % ', '.join(DELS))
        update_expression = ' '.join(components)
        print(update_expression)
        return update_expression, attr_values

    @write_only
    def _manipulate_flags(self, flag_states, arguments):
        self._validate_flag_names(flag_states.keys())
        key = self._gen_key_from_args(arguments)
        update_expression, attr_values = self._gen_update_expression(flag_states)
        try:
            self.table.update_item(
                    Key=self._gen_dynamo_key_from_key(key),
                    UpdateExpression="SET flag_states = :flag_states",
                    ConditionExpression="attribute_not_exists(flag_states)",
                    ExpressionAttributeValues={':flag_states':{}})
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'ConditionalCheckFailedException':
                raise
        self.table.update_item(
                Key=self._gen_dynamo_key_from_key(key),
                UpdateExpression=update_expression,
                ExpressionAttributeValues=attr_values)

    @write_only
    def add_flag(self, flag_name, arguments={}, state=True):
        self._manipulate_flags({flag_name:state}, arguments)

    @write_only
    def add_flags(self, flag_states, arguments={}):
        if type(flag_states) in (list, tuple):
            flag_states = {k:True for k in flag_states}
        elif not isinstance(flag_states, dict):
            print(flag_states)
            raise InvalidFlagStates
        self._manipulate_flags(flag_states, arguments)

    @write_only
    def remove_flag(self, flag_name, arguments={}):
        self._manipulate_flags({flag_name:None}, arguments)

    @write_only
    def remove_flags(self, flag_names, arguments={}):
        flag_states = { k:None for k in flag_names }
        self._manipulate_flags(flag_states, arguments)
