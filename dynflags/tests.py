import unittest
from unittest import mock
from dynflags import ReadOnlyFlagManager, InvalidArgumentKeyTypeException, InvalidArgumentValueTypeException
from moto import mock_dynamodb2
import boto3

class TestGeneral(unittest.TestCase):

    @mock.patch('dynflags.ReadOnlyFlagManager._initialize_table')
    @mock_dynamodb2
    def test_autocreate_isnt_called(self, *args):
        mgr = ReadOnlyFlagManager('my-table')
        self.assertRaises(mgr.dynamo.meta.client.exceptions.ResourceNotFoundException, getattr, mgr, 'table')
        self.assertFalse(mgr._initialize_table.called)
 
    @mock.patch('dynflags.ReadOnlyFlagManager._initialize_table')
    @mock_dynamodb2
    def test_autocreate_is_called(self, *args):
        mgr = ReadOnlyFlagManager('my-table', autocreate_table=True)
        mgr.table # just access the property
        self.assertTrue(mgr._initialize_table.called)

    @mock_dynamodb2
    def test_key_generation_and_reversal(self):
        args = { 'a': '1', 'b': '2' }
        mgr = ReadOnlyFlagManager('my-table')
        key = mgr._gen_key_from_args(args)
        self.assertEqual(args, mgr._gen_args_from_key(key))

    @mock_dynamodb2
    def test_argument_key_validation(self):
        mgr = ReadOnlyFlagManager('my-table')
        args = { 'a': '1' }
        mgr._validate_arguments(args) # accept string key
        args = { 1: 'a' }
        self.assertRaises(InvalidArgumentKeyTypeException, mgr._validate_arguments, args) # deny int key

    @mock_dynamodb2
    def test_argument_value_validation(self):
        mgr = ReadOnlyFlagManager('my-table')
        args = { 'a': '1' }
        mgr._validate_arguments(args) # accept string value
        args = { 'a': 1 }
        self.assertRaises(InvalidArgumentValueTypeException, mgr._validate_arguments, args) # deny int value


if __name__ == "__main__":
    unittest.main()
