"""
main.py
====================================
The core module of dynflags
"""
from __future__ import print_function

from collections import defaultdict

from botocore.exceptions import ClientError
from six import string_types

import boto3
import logging

from .exceptions import *

DEFAULT_TABLE_SPEC = {"BillingMode": 'PAY_PER_REQUEST'}


def write_only(func):
    def block_read_only(self, *args, **kwargs):
        if self._config.read_only:
            raise ReadOnlyException()
        return func(self, *args, **kwargs)

    return block_read_only


def merge(dict1, dict2):
    res = {**dict1, **dict2}
    return res


class Config(dict):
    def __init__(self, table_name, *args, **kwargs):
        default_conf = {
            'boto_config': {'region_name': 'us-east-1'},
            'table_name': table_name,
            'table_config': DEFAULT_TABLE_SPEC.copy(),
            'dynamo': None,
            'cache': None,
            'cached_table_obj': None,
            'autocreate_table': False,
            'read_only': True,
            'consistent_reads': False,
            'logger': logging.getLogger(__name__),
            'robust': False,
            'default_list_key': '__default__'
        }

        configurations = merge(default_conf, kwargs)
        super(Config, self).__init__(*args, **configurations)
        for k, v in configurations.items():
            self[k] = v

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Config, self).__setitem__(key, value)

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Config, self).__delitem__(key)
        del self.__dict__[key]


class DynFlagManager:
    def __init__(self, table_name, **kwargs):
        self._config = Config(table_name, **kwargs)

    @property
    def dynamo(self):
        if not self._config.dynamo:
            self._config.dynamo = boto3.resource('dynamodb', **self._config.boto_config)
        return self._config.dynamo

    @property
    def table(self):
        if self._config.cached_table_obj:
            self._config.logger.debug('Returning cached table object')
            return self._config.cached_table_obj
        self._config.logger.debug('Table object not cached')
        self._config.cached_table_obj = self.dynamo.Table(self._config.table_name)
        try:
            self._config.cached_table_obj.creation_date_time
        except self.dynamo.meta.client.exceptions.ResourceNotFoundException as exc:
            self._config.logger.debug('Table does not exist')
            if self._config.autocreate_table:
                self._initialize_table()
            else:
                raise exc
        return self._config.cached_table_obj

    def _initialize_table(self):
        # create the table
        self._config.logger.debug('Creating DynamoDB Table: %s, %s' %
                           (self._config.table_name, self._config.table_config))
        table = self.dynamo.create_table(TableName=self._config.table_name,
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
                                         **self._config.table_config)
        table.meta.client.get_waiter('table_exists').wait(
            TableName=self._config.table_name)
        self._config.logger.debug('DynamoDB Table Created')

    def _gen_dynamo_key_from_key(self, key):
        return {"arguments": key}

    def _validate_arguments(self, arguments):
        if not all(isinstance(x, string_types) for x in arguments.keys()):
            raise InvalidArgumentKeyTypeException('Argument keys must be strings')
        if not all(isinstance(x, string_types) for x in arguments.values()):
            raise InvalidArgumentValueTypeException('Argument values must be strings')

    def _validate_flags(self, flag_names):
        if isinstance(flag_names, list):
            if not all(isinstance(x, string_types) for x in flag_names):
                raise InvalidFlagNameTypeException('Flags names must be strings')
            return

        if not all(isinstance(x, string_types) for x in flag_names.keys()):
            raise InvalidFlagNameTypeException('Flags names must be strings')

        if not all(isinstance(x, bool) for x in flag_names.values()):
            raise InvalidFlagValueTypeException('Flags values must be either true or false')

    def _validate_action_type(self, action):
        if not action in ('REMOVE', 'ADD', 'PUT'):
            raise InvalidActionTypeException('Action must be either REMOVE, ADD, or PUT')

    def _gen_key_from_args(self, arguments):
        if not arguments:
            return self._config.default_list_key
        self._validate_arguments(arguments)
        arglist = list(arguments.items())
        arglist.sort(key=lambda x: x[0])
        key_fragments = ("%s=%s" % (x, str(y)) for x, y in arglist)
        key = ';'.join(key_fragments)
        self._config.logger.debug('Generated key from args: %s, %s' %
                           (arguments, key))
        return key

    def _gen_args_from_key(self, key):
        args = {}
        for frag in key.split(';'):
            k, v = frag.split("=")
            args[k] = v
        return args

    def _query_dynamodb_for_flags_for_key(self, key):
        self._config.logger.debug('Querying DynamoDB for key: %s' %
                           self._gen_dynamo_key_from_key(key))
        item = self.table.get_item(Key=self._gen_dynamo_key_from_key(key),
                                   ConsistentRead=self._config.consistent_reads)

        flags = item.get('Item', {}).get('flags', {})
        self._config.logger.debug('Found the following flags for key: %s, %s' %
                           (key, flags))

        return flags

    def _get_flags_for_key(self, key, use_cache=True):
        if use_cache and self._config.cache:
            self._config.logger.debug('Checking cache for key: %s' % key)
            cached_flags = self._config.cache.get(key)
            if cached_flags:
                self._config.logger.debug('Returning cached flags for key: %s, %s' %
                                   (key, cached_flags))
                return cached_flags
        flags = self._query_dynamodb_for_flags_for_key(key)
        if use_cache and self._config.cache:
            self._config.logger.debug('Setting cache for key: %s, %s' % (key, flags))
            self._config.cache.set(key, flags)
        return flags

    def _get_flags_for_args(self, arguments, use_cache=True):
        key = self._gen_key_from_args(arguments)
        return self._get_flags_for_key(key, use_cache)

    def _is_active(self, flag_name, arguments={}, use_cache=True):
        self._validate_flags({flag_name: True})
        flags = self._get_flags_for_args(arguments, use_cache)

        return flags.get(flag_name, False)

    @write_only
    def _gen_attr_updates(self, flag_names, action):
        if action == 'REMOVE':
            return dict(
                UpdateExpression='{} {}'.format(action, ','.join(f'flags.{flag_name}' for flag_name in flag_names)),
            )

        return dict(
            UpdateExpression='{} {}'.format(action, ','.join(f'flags.#{k}=:{k}' for k in flag_names)),
            ExpressionAttributeNames={f'#{k}': k for k in flag_names},
            ExpressionAttributeValues={f':{k}': v for k, v in flag_names.items()}
        )

    @write_only
    def _manipulate_flags(self, flag_names, arguments, action):
        self._validate_flags(flag_names)
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
                ExpressionAttributeValues={':flags': flag_names}
            )

    @write_only
    def add_flag(self, flag_name, enabled, arguments={}):
        flag_names = {flag_name: enabled}

        self.add_flags(flag_names, arguments=arguments)

    @write_only
    def add_flags(self, flag_names, arguments={}):
        self._manipulate_flags(flag_names, arguments, 'SET')

    @write_only
    def remove_flag(self, flag_name):
        self.remove_flags([flag_name])

    @write_only
    def remove_flags(self, flag_names, arguments={}):
        self._manipulate_flags(flag_names, arguments, 'REMOVE')

    def is_active(self, *args, **kwargs):
        if self._config.robust:
            try:
                return self._is_active(*args, **kwargs)
            except Exception as exc:
                self._config.logger.error(str(exc))
                return False
        else:
            return self._is_active(*args, **kwargs)

    def get_item_for_key(self, key):
        result = self.table.get_item(
            Key=self._gen_dynamo_key_from_key(key),
            ConsistentRead=self._config.consistent_reads
        )

        item = result['Item']
        return item

    def get_item_for_args(self, arguments):
        key = self._gen_key_from_args(arguments)
        return self.get_item_for_key(key)

    def get_default_flags(self):
        return self._get_flags_for_key(self._config.default_list_key)

    def get_flags_for_args(self, arguments):
        default_flags = self.get_default_flags()
        item_flags = self._get_flags_for_args(arguments)

        return merge(default_flags, item_flags)

    def get_all_flags(self):
        response = self.table.scan()

        flags = defaultdict(dict)
        for item in response.get('Items', []):
            arguments = item.get('arguments')

            for key, value in item.get('flags', {}).items():
                flags[key].update({
                    arguments: value
                })

        return flags
