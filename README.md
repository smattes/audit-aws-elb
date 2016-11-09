audit ELB
============================
This stack will monitor ELB and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor ELB against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;ELB&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-elb/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_ELB_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.


## Required variables with default

### `AUDIT_AWS_ELB_ALERT_LIST`:
  * description: Which alerts would you like to check for? (Default is all ELB alerts)
  * default: elb-old-ssl-policy

### `AUDIT_AWS_ELB_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is true.
  * default: true

### `AUDIT_AWS_ELB_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is always.
  * default: always

### `AUDIT_AWS_ELB_FULL_JSON_REPORT`:
  * description: Would you like to receive the full JSON report? Options - notify / nothing. Default is notify.
  * default: notify

### `AUDIT_AWS_ELB_OWNERS_HTML_REPORT`:
  * description: Would you like to receive the AWS owner tag report? Options - notify / nothing. Default is no / nothing.
  * default: nothing

### `AUDIT_AWS_ELB_ROLLUP_REPORT`:
  * description: Would you like to receive a Summary ELB report? Options - notify / nothing. Default is no / nothing.
  * default: nothing

### `AUDIT_AWS_ELB_DEBUG_REPORT`:
  * description: Would you like to receive an ELB debug report? Options - notify / nothing. Default is no / nothing.
  * default: nothing

### `AUDIT_AWS_ELB_REGIONS`:
  * description: List of AWS regions to check. Default is us-east-1,us-west-1,us-west-2,eu-west-1.
  * default: us-east-1, us-west-1, us-west-2, eu-west-1


## Optional variables with no default

### `AUDIT_AWS_ELB_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of owner of the ELB object. (Optional)
  * default: NOT_A_TAG


## Optional variables with default

### `AUDIT_AWS_ELB_ALERT_NO_OWNER_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications for objects with no owner tag (Optional, only if owner tag is enabled).

## Tags
1. Audit
1. Best Practices
1. Alert
1. ELB

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-elb/master/images/diagram.png "diagram")


## Icon


