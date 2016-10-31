audit ELB
============================
This stack will monitor ELB and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor ELB against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;ELB&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-elb/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_ELB_ALERT_RECIPIENT`:
  * description: email recipient for notification


## Required variables with default

### `AUDIT_AWS_ELB_ALERT_LIST`:
  * description: alert list for generating notifications
  * default: elb-old-ssl-policy

### `AUDIT_AWS_ELB_ALLOW_EMPTY`:
  * description: receive empty reports?
  * default: true

### `AUDIT_AWS_ELB_SEND_ON`:
  * description: always or change
  * default: always

### `AUDIT_AWS_ELB_FULL_JSON_REPORT`:
  * description: notify or nothing
  * default: notify

### `AUDIT_AWS_ELB_OWNERS_HTML_REPORT`:
  * description: notify or nothing
  * default: nothing

### `AUDIT_AWS_ELB_ROLLUP_REPORT`:
  * description: notify or nothing
  * default: nothing

### `AUDIT_AWS_ELB_DEBUG_REPORT`:
  * description: notify or nothing
  * default: nothing

### `AUDIT_AWS_ELB_REGIONS`:
  * description: list of AWS regions to check. Default is us-east-1.
  * default: us-east-1


## Optional variables with no default

### `AUDIT_AWS_ELB_OWNER_TAG`:
  * description: AWS tag whose value is an email address specifying the owner of the ELB object
  * default: NOT_A_TAG


## Optional variables with default

### `AUDIT_AWS_ELB_ALERT_NO_OWNER_RECIPIENT`:
  * description: email recipient for objects with no owner tag if owner tag is enabled

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


