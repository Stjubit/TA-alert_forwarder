
import ta_alert_forwarder_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        'hostname',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=1, 
            max_len=200, 
        )
    ),
    field.RestField(
        'port',
        required=True,
        encrypted=False,
        default=8088,
        validator=validator.Number(
            min_val=1, 
            max_val=65535, 
        )
    ),
    field.RestField(
        'token',
        required=True,
        encrypted=True,
        default=None,
        validator=validator.String(
            min_len=1, 
            max_len=8192, 
        )
    ),
    field.RestField(
        "verify",
        required=False,
        encrypted=False,
        default=True,
        validator=None,
    )
]
model = RestModel(fields, name=None)


endpoint = SingleModel(
    'ta_alert_forwarder_hec',
    model,
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
