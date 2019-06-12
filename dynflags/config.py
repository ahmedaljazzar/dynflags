DEFAULT_TABLE_SPEC = {"BillingMode": 'PAY_PER_REQUEST'}

class DynFlagsConfig(object):
    _defaults = {
            'table_name': 'dynflags',
            'boto_config': {'region_name': 'us-east-1'},
            'table_config': {"BillingMode": 'PAY_PER_REQUEST'},
            'autocreate_table': False,
            'read_only': True,
            'consistent_reads': False,
            'robust': False,
            'default_key': '__defaults__'
        }
    
    def __init__(self, config={}):
        _config = super(DynFlagsConfig, self).__getattribute__('_defaults').copy()
        _config.update(config)
        super(DynFlagsConfig, self).__setattr__('_config', _config)

    def __getattr__(self, key):
        return super(DynFlagsConfig, self).__getattribute__('_config').get(key)

    def __setattr__(self, key, value):
        raise Exception("%s objects are immutable" % self.__class__.__name__)

    def __delattr__(self, key):
        raise Exception("%s objects are immutable" % self.__class__.__name__)

    def __hasattr__(self, key):
        return key in  self._config
