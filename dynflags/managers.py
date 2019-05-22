from __future__ import print_function
from six import string_types

import boto3, datetime

from .exceptions import *

DEFAULT_TABLE_SPEC = {
        "BillingMode": 'PAY_PER_REQUEST'
    }

class ReadOnlyFlagManager:
    def __init__(
            self, table_name, boto_config={ 'region_name': 'us-east-1' }, table_config=None, cache_manager=None,
            autocreate_table=False):
        self.table_name = table_name
        self._autocreate_table = autocreate_table
        self._boto_config = boto_config
        self._dynamo = None
        self._cached_table_obj = None
        self._cache_manager = cache_manager
        self._table_config = table_config or DEFAULT_TABLE_SPEC.copy()

    def log(self, text):
        print(text)

    def _initialize_table(self):
        # create the table
        self.log('Creating DynamoDB Table: %s, %s' % (self.table_name, self._table_config))
        table = self.dynamo.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {
                        "AttributeName": "arguments",
                        "KeyType": "HASH"
                    }
                ],
                AttributeDefinitions=[
                    {
                        "AttributeName": "arguments",
                        "AttributeType": "S"
                    }
                ],
                **self._table_config)
        table.meta.client.get_waiter('table_exists').wait(TableName=self.table_name)
        self.log('DynamoDB Table Created')

    def _gen_dynamo_key_from_key(self, key):
        return { "arguments": key }

    def _validate_arguments(self, arguments):
        if not all(isinstance(x, string_types) for x in arguments.keys()):
            raise InvalidArgumentKeyTypeException('Argument keys must be strings')
        if not all(isinstance(x, string_types) for x in arguments.values()):
            raise InvalidArgumentValueTypeException('Argument values must be strings')

    def _gen_key_from_args(self, arguments):
        if not arguments: return '__global__'
        self._validate_arguments(arguments)
        arglist = list(arguments.items())
        arglist.sort(key=lambda x:x[0])
        key_fragments = ("%s=%s" % (x, str(y)) for x, y in arglist)
        key = ';'.join(key_fragments)
        self.log('Generated key from args: %s, %s' % (arguments, key))
        return key

    def _gen_args_from_key(self, key):
        args = {}
        for frag in key.split(';'):
            k, v = frag.split("=")
            args[k] = v
        return args

    def _query_dynamodb_for_flags_for_key(self, key):
        self.log('Querying DynamoDB for key: %s' % self._gen_dynamo_key_from_key(key))
        item = self.table.get_item(
                Key=self._gen_dynamo_key_from_key(key)
            )
        active_flags = item.get('Item', {}).get('active_flags', set())
        self.log('Found active flags for key: %s, %s' % (key, active_flags))
        return active_flags

    def get_flags_for_key(self, key, use_cache=True):
        if use_cache and self._cache_manager:
            self.log('Checking cache for key: %s' % key)
            cached_flags = self._cache_manager.get_cache_for_key(key)
            if cached_flags:
                self.log('Returning cached flags for key: %s, %s' % (key, cached_flags))
                return cached_flags
        flags = self._query_dynamodb_for_flags_for_key(key)
        if use_cache and self._cache_manager:
            self.log('Setting cache for key: %s, %s' % (key, flags))
            self._cache_manager.set_cache_for_key(key, flags)
        return flags

    @property
    def dynamo(self):
        if not self._dynamo:
            self._dynamo = boto3.resource('dynamodb', **self._boto_config)
        return self._dynamo

    @property
    def table(self):
        if self._cached_table_obj:
            self.log('Returning cached table object')
            return self._cached_table_obj
        self.log('Table object not cached')
        self._cached_table_obj = self.dynamo.Table(self.table_name)
        try:
            self._cached_table_obj.creation_date_time
        except self.dynamo.meta.client.exceptions.ResourceNotFoundException as exc:
            self.log('Table does not exist')
            if self._autocreate_table: self._initialize_table()
            else: raise exc
        return self._cached_table_obj

    def is_active(self, flagname, arguments={}, use_cache=True):
        key = self._gen_key_from_args(arguments)
        active_flags = self.get_flags_for_key(key, use_cache)
        if flagname in active_flags: return True
        return False

    def add_flag(self, flagname, arguments={}):
        raise ReadOnlyException()

    def remove_flag(self, flagname, arguments={}):
        raise ReadOnlyException()

class ReadWriteFlagManager(ReadOnlyFlagManager):
    def _gen_attr_updates(self, flags, action):
        attr_updates = {
                'active_flags': {
                    "Value": set(flags),
                    "Action": action
                },
                'version': {
                    "Value": 1,
                    "Action": "ADD"
                },
                'last_update_time': {
                    "Value": datetime.utcnow().isoformat(),
                    "Action": "PUT"
                }
            }
        return attr_updates

    def _manipulate_flags(self, flagnames, arguments, action):
        if not all(isinstance(flagname, string_types) for flagname in flagnames):
            raise InvalidFlagNameTypeException('Flag names must be strings')
        key = self._gen_key_from_args(arguments)
        self.table.update_item(
                Key=self._gen_dynamo_key_from_key(key),
                AttributeUpdates=self._gen_attr_updates(flagnames, action)
            )
    def add_flag(self, flagname, arguments={}):
        self._manipulate_flags([flagname], arguments, 'ADD')

    def add_flags(self, flagnames, arguments={}):
        self._manipulate_flags(flagnames, arguments, 'ADD')

    def remove_flag(self, flagname, arguments={}):
        self._manipulate_flags([flagname], arguments, 'DELETE')

    def remove_flags(self, flagnames, arguments={}):
        self._manipulate_flags(flagnames, arguments, 'DELETE')
