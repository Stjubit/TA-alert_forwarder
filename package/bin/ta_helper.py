"""
Helper functions used by multiple apps and add-ons
"""

import import_declare_test
import logging
import splunklib.client

from solnlib import conf_manager, log, utils
from solnlib.modular_input import checkpointer


def initalize_logger(
    input_type: str, input_name: str, settings_conf_name: str, session_key
) -> logging.Logger:
    """
    This function initializes a logging.Logger object for Splunk using
    the solnlib library.
    """
    logger = log.Logs().get_logger(
        f"{import_declare_test.ADDON_NAME}_{input_type}_{input_name}"
    )

    # fetch log level from TA configuration and set it for logger
    log_level = conf_manager.get_log_level(
        logger=logger,
        session_key=session_key,
        app_name=import_declare_test.ADDON_NAME,
        conf_name=settings_conf_name,
    )
    logger.setLevel(log_level)

    return logger


def get_account_details(
    logger: logging.Logger, session_key: str, account_conf_name: str, account_name: str
) -> dict:
    """
    This function reads account configuration from Splunk using solnlib and
    returns it as dict.

    Returns None if account configuration could not be read.
    """
    cfm = conf_manager.ConfManager(
        session_key=session_key,
        app=import_declare_test.ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{import_declare_test.ADDON_NAME}#configs/conf-{account_conf_name}",
    )
    try:
        account_conf_file = cfm.get_conf(account_conf_name)
        return account_conf_file.get(account_name)
    except Exception as ex:
        log.log_exception(
            logger,
            ex,
            "Account Read Error",
            msg_before=f"Unable to read account {account_name} in configuration file {account_conf_name}",
        )
        return None


def initialize_splunklib_client(
    server_uri: str, session_key: str
) -> splunklib.client.Service:
    """
    This function initializes a splunklib client
    """
    dscheme, dhost, dport = utils.extract_http_scheme_host_port(server_uri)
    splunklib_client = splunklib.client.connect(
        host=dhost,
        port=dport,
        scheme=dscheme,
        app=import_declare_test.ADDON_NAME,
        token=session_key,
    )

    return splunklib_client


def initialize_checkpointer(
    logger: logging.Logger, server_uri: str, collection_name: str, session_key: str
) -> checkpointer.KVStoreCheckpointer:
    """
    This function initializes a KV Store Checkpointer.

    Returns None if KVStore Collection can not be read.
    """
    dscheme, dhost, dport = utils.extract_http_scheme_host_port(server_uri)

    try:
        checkpoint = checkpointer.KVStoreCheckpointer(
            f"{import_declare_test.ADDON_NAME}_checkpointer",
            session_key,
            import_declare_test.ADDON_NAME,
            scheme=dscheme,
            host=dhost,
            port=dport,
        )
        return checkpoint
    except Exception as ex:
        log.log_exception(
            logger,
            ex,
            "KVStore Collection Read Error",
            msg_before=f"Unable to read KVStore collection {collection_name}",
        )
        return None
