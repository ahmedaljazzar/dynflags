"""
main.py
====================================
The core module of dynflags
"""
from __future__ import print_function

from botocore.exceptions import ClientError
from six import string_types

import boto3
import logging

from .exceptions import *

DEFAULT_TABLE_SPEC = {"BillingMode": 'PAY_PER_REQUEST'}
DEFAULT_LIST_KEY = '__default__'


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

    def _validate_flag_names(self, flag_names):
        return
        if not all(isinstance(x, dict) for x in flag_names):
            raise InvalidFlagNameTypeException('Flags must be dictionaries')

    def _validate_action_type(self, action):
        if not action in ('REMOVE', 'ADD', 'PUT'):
            raise InvalidActionTypeException('Action must be either REMOVE, ADD, or PUT')

    def _gen_key_from_args(self, arguments):
        if not arguments:
            return DEFAULT_LIST_KEY
        self._validate_arguments(arguments)
        arglist = list(arguments.items())
        arglist.sort(key=lambda x: x[0])
        key_fragments = ("%s=%s" % (x, str(y)) for x, y in arglist)
        key = ';'.join(key_fragments)
        self._logger.debug('Generated key from args: %s, %s' %
                           (arguments, key))
        return key

    def _gen_args_from_key(self, key):
        args = {}
        for frag in key.split(';'):
            k, v = frag.split("=")
            args[k] = v
        return args

    def _query_dynamodb_for_flags_for_key(self, key):
        self._logger.debug('Querying DynamoDB for key: %s' %
                           self._gen_dynamo_key_from_key(key))
        item = self.table.get_item(Key=self._gen_dynamo_key_from_key(key),
                                   ConsistentRead=self._consistent_reads)

        flags = item.get('Item', {}).get('flags', set())
        self._logger.debug('Found the following flags for key: %s, %s' %
                           (key, flags))

        return flags

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

    def is_active(self, *args, **kwargs):
        if self._robust:
            try:
                return self._is_active(*args, **kwargs)
            except Exception as exc:
                self._logger.error(str(exc))
                return False
        else:
            return self._is_active(*args, **kwargs)

    def _is_active(self, flag_name, arguments={}, use_cache=True):
        # TODO: Edit to match the new logic
        self._validate_flag_names([flag_name])
        active_flags = self.get_flags_for_args(arguments, use_cache)
        if flag_name in active_flags:
            return True
        return False

    def _merge_flags(self, flag_names):
        new = {}

        for flag_name in flag_names:
            for k, v in flag_name.items():
                new[k] = v

        return new

    @write_only
    def _gen_attr_updates(self, flag_names, action):
        if action == 'REMOVE':
            return dict(
                UpdateExpression='{} {}'.format(action, ','.join(f'flags.{flag_name}' for flag_name in flag_names)),
            )

        new = self._merge_flags(flag_names)
        return dict(
            UpdateExpression='{} {}'.format(action, ','.join(f'flags.#{k}=:{k}' for k in new)),
            ExpressionAttributeNames={f'#{k}': k for k in new},
            ExpressionAttributeValues={f':{k}': v for k, v in new.items()}
        )

    @write_only
    def _manipulate_flags(self, flag_names, arguments, action):
        self._validate_flag_names(flag_names)
        key = self._gen_key_from_args(arguments)
        dynamo_key = self._gen_dynamo_key_from_key(key)

        try:
            self.table.update_item(
                Key=dynamo_key,
                **self._gen_attr_updates(flag_names, action)
            )
        except ClientError:
            self.table.update_item(
                Key=dynamo_key,
                UpdateExpression='SET flags = :flags',
                ExpressionAttributeValues={':flags': self._merge_flags(flag_names)}
            )

    @write_only
    def add_flag(self, flag_name, enabled, arguments={}):
        flag = {flag_name: enabled}

        self.add_flags([flag], arguments=arguments)

    @write_only
    def add_flags(self, flag_names, arguments={}):
        self._manipulate_flags(flag_names, arguments, 'SET')

    @write_only
    def remove_flag(self, flag_name):
        self.remove_flags([flag_name])

    @write_only
    def remove_flags(self, flag_names, arguments={}):
        self._manipulate_flags(flag_names, arguments, 'REMOVE')

    def get_flag_names(self, key=None, arguments=None):
        if key:
            item = self.get_item_for_key(key)
            return item['flags']
        elif arguments:

            default_item = self.get_item_for_key(DEFAULT_LIST_KEY)
            default_flags = default_item['flags']

            item = self.get_item_for_args(arguments)
            item_flags = item['flags']

            return self._merge(default_flags, item_flags)

        flag_names = {}
        response = self.table.scan()
        for item in response['Items']:
            flag_names.update(item['flags'])

        return flag_names

    def _merge(self, dict1, dict2):
        res = {**dict1, **dict2}
        return res
