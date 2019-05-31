"""
main.py
====================================
The core module of dynflags
"""
from __future__ import print_function

from datetime import datetime, timezone
from six import string_types

import boto3
import logging

from .exceptions import *

DEFAULT_TABLE_SPEC = {"BillingMode": 'PAY_PER_REQUEST'}
GLOBAL_LIST_KEY = '__global__'


def write_only(func):
    def block_read_only(self, *args, **kwargs):
        if self._read_only:
            raise ReadOnlyException()
        return func(self, *args, **kwargs)

    return block_read_only


class DynFlagManager:
    def __init__(self,
                 table_name,
                 boto_config={'region_name': 'us-east-1'},
                 table_config=None,
                 cache=None,
                 autocreate_table=False,
                 read_only=True,
                 consistent_reads=False,
                 logger=None,
                 robust=False):
        self._table_name = table_name
        self._autocreate_table = autocreate_table
        self._boto_config = boto_config
        self._dynamo = None
        self._cached_table_obj = None
        self._cache = cache
        self._table_config = table_config or DEFAULT_TABLE_SPEC.copy()
        self._read_only = read_only
        self._consistent_reads = consistent_reads
        self._logger = logger or logging.getLogger(__name__)
        self._robust = robust

    def _initialize_table(self):
        # create the table
        self._logger.debug('Creating DynamoDB Table: %s, %s' %
                           (self._table_name, self._table_config))
        table = self.dynamo.create_table(TableName=self._table_name,
                                         KeySchema=[{
                                             "AttributeName": "arguments",
                                             "KeyType": "HASH"
                                         }],
                                         AttributeDefinitions=[{
                                             "AttributeName":
                                             "arguments",
                                             "AttributeType":
                                             "S"
                                         }, {
                                             "AttributeName":
                                             "active_flags",
                                             "AttributeType":
                                             "S"
                                         }],
                                         GlobalSecondaryIndexes=[{
                                             'IndexName':
                                             'active_flags',
                                             'KeySchema': [{
                                                 'AttributeName':
                                                 'active_flags',
                                                 'KeyType': 'HASH'
                                             }],
                                             'Projection': {
                                                 'ProjectionType': 'ALL',
                                             }
                                         }],
                                         **self._table_config)
        table.meta.client.get_waiter('table_exists').wait(
            TableName=self._table_name)
        self._logger.debug('DynamoDB Table Created')

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

    def _validate_action_type(self, action):
        if not action in ('DELETE', 'ADD', 'PUT', 'EXCLUDE'):
            raise InvalidActionTypeException('Action must be either DELETE, ADD, PUT, or EXCLUDE')

    def _gen_key_from_args(self, arguments):
        if not arguments:
            return GLOBAL_LIST_KEY
        self._validate_arguments(arguments)
        arglist = list(arguments.items())
        arglist.sort(key=lambda x: x[0])
        key_fragments = ("%s=%s" % (x, str(y)) for x, y in arglist)
        key = ';'.join(key_fragments)
        self._logger.debug('Generated key from args: %s, %s' %
                           (arguments, key))
        return key

    def _filter_global_flags(self, flags):
        global_flags = self.get_flags_for_key(GLOBAL_LIST_KEY)

        not_globals = list(set(flags) - global_flags)
        in_globals = list(set(flags) & global_flags)

        return in_globals, not_globals

    def _gen_args_from_key(self, key):
        args = {}
        for frag in key.split(';'):
            k, v = frag.split("=")
            args[k] = v
        return args

    def _gen_actions(self, action):
        self._validate_action_type(action)

        if action == 'EXCLUDE':
            active_flags_action = 'DELETE'
            excluded_flags_action = 'ADD'
        elif action == 'DELETE':
            active_flags_action = 'DELETE'
            excluded_flags_action = 'DELETE'
        elif action == 'PUT':
            active_flags_action = 'PUT'
            excluded_flags_action = 'DELETE'
        else:
            active_flags_action = 'ADD'
            excluded_flags_action = 'DELETE'

        return active_flags_action, excluded_flags_action

    def _query_dynamodb_for_flags_for_key(self, key):
        self._logger.debug('Querying DynamoDB for key: %s' %
                           self._gen_dynamo_key_from_key(key))
        item = self.table.get_item(Key=self._gen_dynamo_key_from_key(key),
                                   ConsistentRead=self._consistent_reads)
        active_flags = item.get('Item', {}).get('active_flags', set())
        self._logger.debug('Found active flags for key: %s, %s' %
                           (key, active_flags))
        return active_flags

    def get_flags_for_key(self, key, use_cache=True):
        if use_cache and self._cache:
            self._logger.debug('Checking cache for key: %s' % key)
            cached_flags = self._cache.get(key)
            if cached_flags:
                self._logger.debug('Returning cached flags for key: %s, %s' %
                                   (key, cached_flags))
                return cached_flags
        flags = self._query_dynamodb_for_flags_for_key(key)
        if use_cache and self._cache:
            self._logger.debug('Setting cache for key: %s, %s' % (key, flags))
            self._cache.set(key, flags)
        return flags

    def get_flags_for_args(self, arguments, use_cache=True):
        key = self._gen_key_from_args(arguments)
        return self.get_flags_for_key(key, use_cache)

    def get_item_for_key(self, key):
        result = self.table.get_item(
            Key=self._gen_dynamo_key_from_key(key),
            ConsistentRead=self._consistent_reads
        )

        item = result['Item']
        return item

    def get_item_for_args(self, arguments):
        key = self._gen_key_from_args(arguments)
        return self.get_item_for_key(key)

    @property
    def dynamo(self):
        if not self._dynamo:
            self._dynamo = boto3.resource('dynamodb', **self._boto_config)
        return self._dynamo

    @property
    def table(self):
        if self._cached_table_obj:
            self._logger.debug('Returning cached table object')
            return self._cached_table_obj
        self._logger.debug('Table object not cached')
        self._cached_table_obj = self.dynamo.Table(self._table_name)
        try:
            self._cached_table_obj.creation_date_time
        except self.dynamo.meta.client.exceptions.ResourceNotFoundException as exc:
            self._logger.debug('Table does not exist')
            if self._autocreate_table:
                self._initialize_table()
            else:
                raise exc
        return self._cached_table_obj

    def is_active(self, *args, **kwargs):
        if self._robust:
            try:
                return self._is_active(*args, **kwargs)
            except Exception as exc:
                self._logger.error(str(exc))
                return False
        else:
            return self._is_active(*args, **kwargs)

    def _is_active(self, flagname, arguments={}, use_cache=True):
        self._validate_flag_names([flagname])
        active_flags = self.get_flags_for_args(arguments, use_cache)
        if flagname in active_flags:
            return True
        return False

    @write_only
    def _gen_attr_updates(self, flags, action):
        active_flags_action, excluded_flags_action = self._gen_actions(action)

        attr_updates = {
            'active_flags': {
                "Value": set(flags),
                "Action": active_flags_action
            },
            'excluded_flags': {
                "Value": set(flags),
                "Action": excluded_flags_action
            },
            'version': {
                "Value": 1,
                "Action": "ADD"
            },
            'last_update_time': {
                "Value": datetime.now(timezone.utc).astimezone().isoformat(),
                "Action": "PUT"
            }
        }
        return attr_updates

    @write_only
    def _manipulate_flags(self, flagnames, arguments, action):
        self._validate_flag_names(flagnames)
        key = self._gen_key_from_args(arguments)
        self.table.update_item(
            Key=self._gen_dynamo_key_from_key(key),
            AttributeUpdates=self._gen_attr_updates(flagnames, action)
        )

    @write_only
    def add_flag(self, flagname, arguments={}):
        self._manipulate_flags([flagname], arguments, 'ADD')

    @write_only
    def add_flags(self, flagnames, arguments={}):
        self._manipulate_flags(flagnames, arguments, 'ADD')

    @write_only
    def exclude_flag(self, flagname, arguments):
        self.exclude_flags([flagname], arguments)

    @write_only
    def exclude_flags(self, flagnames, arguments):
        in_globals, not_globals = self._filter_global_flags(flagnames)

        if not_globals:
            self._logger.info('Did not exclude {} as those flags are not in the global list')

        if not in_globals:
            raise InvalidFlagsException('Cannot exclude flags that do not exist in the global list')

        self._manipulate_flags(in_globals, arguments, 'EXCLUDE')

    @write_only
    def remove_flag(self, flagname, arguments):
        self._manipulate_flags([flagname], arguments, 'DELETE')

    @write_only
    def remove_flags(self, flagnames, arguments={}):
        self._manipulate_flags(flagnames, arguments, 'DELETE')
