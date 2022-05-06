# Alert Forwarder for Splunk

This Splunk Technical Add-on adds an Alert Action, which you can use to forward Splunk Alerts to a HTTP Event Collector (HEC).

## Configuration

The Setup of this TA is pretty simple. Here are the required steps:

- Install the TA on your Splunk instance(s), which should forward Splunk Alerts
- Open the `Alert Forwarder for Splunk` App
  ![Navigation Bar Entry](/screenshots/nav_bar.jpg "Navigation Bar Entry")
- Add a new HTTP Event Collector
  ![App Config Page](/screenshots/config_page.jpg "App Config Page")
- Fill in the values of the destination HEC
  ![HEC Config](/screenshots/hec_config.jpg "HEC Config")
- Optionally, configure proxy and/or logging settings
  ![Proxy/Logging Config](/screenshots/proxy_logging.jpg "Proxy/Logging Config")
- Open the Splunk Alert you want to forward and add the `Forward to Splunk HEC` Alert Action
  ![Alert Action Config](/screenshots/alert_action.jpg "Alert Action Config")

## How to dev

This project uses Docker Compose to spin up a full development environment with two Splunk instances.

- Put your Splunk developer license in the root of this repository in a file called `splunk.lic`
- Create a file with the name `splunkbase.credentials` in the root of this repository and add working Splunkbase credentials in it *(hint: BugMeNot)*:

```
SPLUNKBASE_USERNAME=<username>
SPLUNKBASE_PASSWORD=<password>
```

- Start the Docker instances: `docker compose up [-d]`

That's it. Splunk Alerts are automatically generated, you can begin development and don't have to bother with app setup and custom configurations!

### splmaster001

This Splunk instance retrieves test alerts from `splslave001` and stores them in a pre-configured index called `alerts`.
The HTTP Event Collector (HEC) is automatically enabled by Splunk Ansible.

### splslave001

This Splunk instance generates test alerts and sends them to `splmaster001`.
The app configuration and Saved Searches is already set, so you just have to spin up the instance via Docker Compose.
