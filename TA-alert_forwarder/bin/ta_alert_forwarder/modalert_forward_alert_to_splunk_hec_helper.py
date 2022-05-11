# encoding = utf-8
import splunklib.client
import aob_py3.splunk_aoblib.setup_util as setup_util
import json
import requests
import re
import uuid

from aob_py3.splunktaucclib.global_config import GlobalConfig, GlobalConfigSchema


def send_request_to_hec(
    helper,
    hec_hostname,
    hec_port,
    hec_token,
    verify,
    field_list,
    index="",
    host="",
    source="",
    sourcetype="",
):
    # build URL and prepare payload
    url = "https://{}:{}/services/collector".format(hec_hostname, hec_port)
    helper.log_debug("Request URL: {}".format(url))

    payload = {
        "event": json.dumps(field_list),
    }

    # add optional fields to payload
    if index:
        payload["index"] = index
    if host:
        payload["host"] = host
    if source:
        payload["source"] = source
    if sourcetype:
        payload["sourcetype"] = sourcetype

    helper.log_debug("HEC payload: {}".format(payload))

    try:
        # send request to HEC
        response = requests.post(
            url,
            headers={"Authorization": "Splunk {}".format(hec_token)},
            data=json.dumps(payload),
            verify=True if verify == 1 else False,
            timeout=30,
        )
    except Exception as ex:
        helper.log_error("Received exception in request to HEC: {}".format(str(ex)))
        return False

    helper.log_debug("HEC response: {}".format(response.text))

    # check if response is valid
    resp_json = response.json()
    resp_valid = False

    if "text" in resp_json and resp_json["text"] == "Success":
        resp_valid = True

    if resp_valid == False:
        helper.log_error("Unknown HEC response: {}".format(resp_json))

    return resp_valid


def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]
    [sample_code_macro:end]
    """

    helper.log_info("Forward Alert to Splunk HEC Alert Action started ...")
    helper.set_log_level(helper.log_level)

    # get alert action configuration
    splunk_hec_target = helper.get_param("splunk_hec_target")
    index = helper.get_param("index")
    host = helper.get_param("host")
    source = helper.get_param("source")
    sourcetype = helper.get_param("sourcetype")
    regex_field_exclusions = helper.get_param("regex_field_exclusions")

    # add non-customizable field exclusions to the list
    if not regex_field_exclusions:
        regex_field_exclusions = []
    else:
        regex_field_exclusions = regex_field_exclusions.split(",")

    regex_field_exclusions.extend(["^__mv_.*$"])

    # fetch HEC configuration
    with open(setup_util.get_schema_path()) as f:
        json_schema = "".join([l for l in f])
        global_config = GlobalConfig(
            helper.splunk_uri,
            helper.session_key,
            GlobalConfigSchema(json.loads(json_schema)),
        )

    all_hec_configs = global_config.configs.load().get("hec", [])
    hec_config = [x for x in all_hec_configs if x["name"] == splunk_hec_target]

    if len(hec_config) == 0:
        helper.log_critical(
            "Unable to find HEC configuration for target {}".format(splunk_hec_target)
        )

    hec_hostname = hec_config[0]["hostname"]
    hec_port = hec_config[0]["port"]
    hec_token = hec_config[0]["token"]
    hec_verify = hec_config[0]["verify"]

    helper.log_debug(
        "Alert Action has been started with the following configuration: HEC Hostname={}, HEC Port={}, HEC Verify={}, Index={}, Host={}, Source={}, Sourcetype={}, Field Exclusions={}".format(
            hec_hostname,
            hec_port,
            hec_verify,
            index,
            host,
            source,
            sourcetype,
            regex_field_exclusions,
        )
    )

    # prepare event to forward
    alert = {
        "alert": helper.search_name,
        "alert_id": str(uuid.uuid4()),
        "sid": helper.sid,
        "rid": helper.rid,
        "results_link": helper.settings["results_link"],
        "events": [],
    }

    # add search results to event
    events = helper.get_events()
    skipped_field_names = []
    for event in events:
        event_to_forward = {}

        for field in event:
            # only add fields that are not in the Regex field exclusion list
            for exclusion in regex_field_exclusions:
                if re.match(exclusion.strip(), field.strip()):
                    if (field.strip() in skipped_field_names) == False:
                        skipped_field_names.append(field.strip())
                else:
                    event_to_forward[field] = event[field]

        alert["events"].append(event_to_forward)

    helper.log_debug(
        "Skipped fields because they match exclusion regex patterns: {}".format(
            ",".join(skipped_field_names)
        )
    )

    # fetch alert from Splunk to add alert description and severity
    splunklib_client = splunklib.client.connect(
        token=helper.session_key, owner="-", app="-", sharing=None
    )
    if (helper.search_name in splunklib_client.saved_searches) == False:
        helper.log_warn(
            'Unable to fetch Saved Search "{}" - can\'t add Alert Description and Severity!'.format(
                helper.search_name
            )
        )
    else:
        saved_search = splunklib_client.saved_searches[helper.search_name]

        # add description
        if ("description" in saved_search) == False:
            helper.log_warn(
                'Cannot find Description in Saved Search "{}": Unable to add it to the event!'.format(
                    helper.search_name
                )
            )
        else:
            alert["description"] = saved_search["description"]

        # add severity
        if ("alert.severity" in saved_search) == False:
            helper.log_warn(
                'Cannot find Alert Severity (alert.severity) in Saved Search "{}": Unable to add it to the event!'.format(
                    helper.search_name
                )
            )
        else:
            alert["severity"] = saved_search["alert.severity"]

    # send event to HEC
    success = send_request_to_hec(
        helper,
        hec_hostname,
        hec_port,
        hec_token,
        hec_verify,
        alert,
        index,
        host,
        source,
        sourcetype,
    )

    if success == False:
        helper.log_critical("Unable to forward alert to HEC!")
        return 1

    helper.log_info("Successfully forwarded alert to HEC!")
    return 0
