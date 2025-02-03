# encoding = utf-8
import splunklib.client
import json
import requests
import re
import uuid
import ta_helper
import time

from splunktaucclib.alert_actions_base import ModularAlertBase


def send_request_to_hec(
    helper: ModularAlertBase,
    hec_hostname,
    hec_port,
    hec_token,
    verify,
    field_list,
    retry_count=3,
    timeout=30,
    sleep_interval=60,
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

    # send request to HEC
    for i in range(0, retry_count):
        helper.log_info(
            f"Sending request to HEC to forward alert data (attempt #{i+1}/{retry_count}) ..."
        )

        try:
            response = requests.post(
                url,
                headers={"Authorization": "Splunk {}".format(hec_token)},
                data=json.dumps(payload),
                verify=True if verify == 1 else False,
                timeout=timeout,
            )
            response.raise_for_status()

            # break if request was successful (do not retry)
            break
        except Exception as ex:
            helper.log_warn(
                f"Received exception in request #{i+1}/{retry_count} to HEC: {ex}"
            )

            if (i + 1) >= retry_count:
                # last retry, fail
                return False

            # sleep configured seconds before retrying request
            time.sleep(sleep_interval)

    helper.log_debug("HEC response: {}".format(response.text))

    # check if response is valid
    resp_json = response.json()
    resp_valid = False

    if "text" in resp_json and resp_json["text"] == "Success":
        resp_valid = True

    if resp_valid is False:
        helper.log_error("Unknown HEC response: {}".format(resp_json))

    return resp_valid


def process_event(helper: ModularAlertBase, *args, **kwargs):
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
    hec_account = ta_helper.get_account_details(
        helper.logger, helper.session_key, "ta_alert_forwarder_hec", splunk_hec_target
    )

    if not hec_account:
        helper.log_error(
            f"Unable to fetch HEC configuration for account {hec_account}. Stopping alert action ..."
        )
        return 1

    hec_hostname = hec_account["hostname"]
    hec_port = hec_account["port"]
    hec_token = hec_account["token"]
    hec_verify = hec_account["verify"]
    hec_retry = (
        int(hec_account["retry_count"]) if "retry_count" in hec_account else 3
    )  # fallback for TA update
    hec_timeout = (
        int(hec_account["timeout"]) if "timeout" in hec_account else 30
    )  # fallback for TA update
    hec_sleep_interval = (
        int(hec_account["sleep_interval"]) if "sleep_interval" in hec_account else 60
    )  # fallback for TA update

    helper.log_debug(
        "Alert Action has been started with the following configuration: HEC Hostname={}, HEC Port={}, HEC Verify={}, Index={}, Host={}, Source={}, Sourcetype={}, Field Exclusions={}, Retry Count={}, Timeout={}, Sleep Interval={}".format(
            hec_hostname,
            hec_port,
            hec_verify,
            index,
            host,
            source,
            sourcetype,
            regex_field_exclusions,
            hec_retry,
            hec_timeout,
            hec_sleep_interval,
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
                    if (field.strip() in skipped_field_names) is False:
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
    if (helper.search_name in splunklib_client.saved_searches) is False:
        helper.log_warn(
            'Unable to fetch Saved Search "{}" - can\'t add Alert Description and Severity!'.format(
                helper.search_name
            )
        )
    else:
        saved_search = splunklib_client.saved_searches[helper.search_name]

        # add description
        if ("description" in saved_search) is False:
            helper.log_warn(
                'Cannot find Description in Saved Search "{}": Unable to add it to the event!'.format(
                    helper.search_name
                )
            )
        else:
            alert["description"] = saved_search["description"]

        # add severity
        if ("alert.severity" in saved_search) is False:
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
        hec_retry,
        hec_timeout,
        hec_sleep_interval,
        index,
        host,
        source,
        sourcetype,
    )

    if success is False:
        helper.log_error("Unable to forward alert to HEC! See TA log for more details.")
        return 1

    helper.log_info("Successfully forwarded alert to HEC!")
    return 0
