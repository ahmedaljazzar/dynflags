import boto3, dynflags, unittest
import moto
from moto import mock_dynamodb2
from unittest import mock


class TestGeneral(unittest.TestCase):
    @mock_dynamodb2
    @mock.patch('dynflags.DynFlagManager._initialize_table')
    def test_autocreate_isnt_called(self, *args):
        mgr = dynflags.DynFlagManager('my-table')
        self.assertRaises(
            mgr.dynamo.meta.client.exceptions.ResourceNotFoundException,
            getattr, mgr, 'table')
        self.assertFalse(mgr._initialize_table.called)

    @mock_dynamodb2
    @mock.patch('dynflags.DynFlagManager._initialize_table')
    def test_autocreate_is_called(self, *args):
        mgr = dynflags.DynFlagManager('my-table', autocreate_table=True)
        mgr.table  # just access the property
        self.assertTrue(mgr._initialize_table.called)

    @mock_dynamodb2
    def test_key_generation_and_reversal(self):
        args = {'a': '1', 'b': '2'}
        mgr = dynflags.DynFlagManager('my-table')
        key = mgr._gen_key_from_args(args)
        self.assertEqual(args, mgr._gen_args_from_key(key))

    @mock_dynamodb2
    def test_argument_key_validation(self):
        mgr = dynflags.DynFlagManager('my-table')
        args = {'a': '1'}
        mgr._validate_arguments(args)  # accept string key
        args = {1: 'a'}
        self.assertRaises(dynflags.InvalidArgumentKeyTypeException,
                          mgr._validate_arguments, args)  # deny int key

    @mock_dynamodb2
    def test_argument_value_validation(self):
        mgr = dynflags.DynFlagManager('my-table')
        args = {'a': '1'}
        mgr._validate_arguments(args)  # accept string value
        args = {'a': 1}
        self.assertRaises(dynflags.InvalidArgumentValueTypeException,
                          mgr._validate_arguments, args)  # deny int value

    @mock_dynamodb2
    def test_flag_name_validation(self):
        mgr = dynflags.DynFlagManager('my-table')
        good_flags = ['flag-name', 'other-flag-name']
        bad_flags = ['flag-name', 1]
        mgr._validate_flag_names(good_flags)
        self.assertRaises(dynflags.InvalidFlagNameTypeException,
                          mgr._validate_flag_names, bad_flags)


class TestReadOnly(unittest.TestCase):
    @mock_dynamodb2
    def test_add_flag_raises_exception(self, *args):
        mgr = dynflags.DynFlagManager('my-table')
        self.assertRaises(dynflags.ReadOnlyException, mgr.add_flag, 'my-flag')

    @mock_dynamodb2
    def test_add_flags_raises_exception(self, *args):
        mgr = dynflags.DynFlagManager('my-table')
        self.assertRaises(dynflags.ReadOnlyException, mgr.add_flags,
                          ['my-flag'])

    @mock_dynamodb2
    def test_remove_flag_raises_exception(self, *args):
        mgr = dynflags.DynFlagManager('my-table')
        self.assertRaises(dynflags.ReadOnlyException, mgr.remove_flag,
                          'my-flag')

    @mock_dynamodb2
    def test_remove_flags_raises_exception(self, *args):
        mgr = dynflags.DynFlagManager('my-table')
        self.assertRaises(dynflags.ReadOnlyException, mgr.remove_flags,
                          ['my-flag'])


class TestReadWrite(unittest.TestCase):
    @mock_dynamodb2
    def test_single_global_flag(self, *args):
        mgr = dynflags.DynFlagManager('my-table',
                                      autocreate_table=True,
                                      read_only=False)
        flag_name = 'my-flag-1'
        self.assertFalse(mgr.is_active(flag_name))
        mgr.add_flag(flag_name)
        self.assertTrue(mgr.is_active(flag_name))

    @mock_dynamodb2
    def test_double_global_flag(self, *args):
        mgr = dynflags.DynFlagManager('my-table',
                                      autocreate_table=True,
                                      read_only=False)
        flag_names = ['my-flag-2', 'my-second-flag-1']
        for flag_name in flag_names:
            self.assertFalse(mgr.is_active(flag_name))
        mgr.add_flags(flag_names)
        for flag_name in flag_names:
            self.assertTrue(mgr.is_active(flag_name))

    @mock_dynamodb2
    def test_single_keyed_flag(self, *args):
        mgr = dynflags.DynFlagManager('my-table',
                                      autocreate_table=True,
                                      read_only=False)
        flag_name = 'my-flag-3'
        args = {'mykey': 'myvalue'}
        self.assertFalse(mgr.is_active(flag_name))
        self.assertFalse(mgr.is_active(flag_name, args))
        mgr.add_flag(flag_name, args)
        self.assertFalse(mgr.is_active(flag_name))
        self.assertTrue(mgr.is_active(flag_name, args))

    @mock_dynamodb2
    def test_double_keyed_flag(self, *args):
        mgr = dynflags.DynFlagManager('my-table',
                                      autocreate_table=True,
                                      read_only=False)
        flag_names = ['my-flag-4', 'my-second-flag-2']
        args = {'mykey': 'myvalue'}
        for flag_name in flag_names:
            self.assertFalse(mgr.is_active(flag_name))
            self.assertFalse(mgr.is_active(flag_name, args))
        mgr.add_flags(flag_names, args)
        for flag_name in flag_names:
            self.assertFalse(mgr.is_active(flag_name))
            self.assertTrue(mgr.is_active(flag_name, args))

    @mock_dynamodb2
    def test_sequential_add(self, *args):
        mgr = dynflags.DynFlagManager('my-table',
                                      autocreate_table=True,
                                      read_only=False)
        flag_names = ['my-flag-5', 'my-second-flag-3']
        for flag_name in flag_names:
            self.assertFalse(mgr.is_active(flag_name))
        for flag_name in flag_names:
            mgr.add_flag(flag_name)
        for flag_name in flag_names:
            self.assertTrue(mgr.is_active(flag_name))

    @mock_dynamodb2
    def test_multiple_single_flag_edit_sequence(self, *args):
        mgr = dynflags.DynFlagManager('my-table',
                                      autocreate_table=True,
                                      read_only=False)
        flag_names = [str(x) for x in range(10)]
        for flag_name in flag_names:
            self.assertFalse(mgr.is_active(flag_name))

        first_add = flag_names[:2]
        mgr.add_flags(first_add)
        for flag_name in first_add:
            self.assertTrue(mgr.is_active(flag_name))

        second_add = flag_names[1:]
        mgr.add_flags(second_add)
        for flag_name in flag_names:
            self.assertTrue(mgr.is_active(flag_name))

        first_remove = flag_names[-2:]
        mgr.remove_flags(first_remove)
        for flag_name in first_remove:
            self.assertFalse(mgr.is_active(flag_name))
        for flag_name in flag_names[:-2]:
            self.assertTrue(mgr.is_active(flag_name))

        second_remove = flag_names[:2]
        for flag_name in second_remove:
            mgr.remove_flag(flag_name)
        for flag_name in flag_names[2:-2]:
            self.assertTrue(mgr.is_active(flag_name))
        for flag_name in (flag_names[-2:] + flag_names[:2]):
            self.assertFalse(mgr.is_active(flag_name))

    @mock_dynamodb2
    def test_robust_read(self, *args):
        mgr = dynflags.DynFlagManager('my-table', autocreate_table=True)
        self.assertRaises(dynflags.InvalidFlagNameTypeException, mgr.is_active,
                          123)

        mgr = dynflags.DynFlagManager('my-table',
                                      autocreate_table=True,
                                      robust=True)
        mgr.is_active(123)


class TestCachedRead(unittest.TestCase):
    @mock_dynamodb2
    def test_cached_read(self, *args):
        class TestCache:
            cache = {}

            def get(self, key):
                return self.cache.get(key)

            def set(self, key, value):
                self.cache[key] = value

        cache = TestCache()

        mgr = dynflags.DynFlagManager('my-table',
                                      autocreate_table=True,
                                      cache=TestCache())
        self.assertFalse(mgr.is_active('test'))
        self.assertTrue('__global__' in cache.cache)
        cache.cache['__global__'] = ['test']
        self.assertTrue(mgr.is_active('test'))
