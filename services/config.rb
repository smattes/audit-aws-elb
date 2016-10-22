coreo_aws_advisor_alert "elb-inventory" do
  action :define
  service :elb
  display_name "ELB Object Inventory"
  description "This rule performs an inventory on all ELB's in the target AWS account."
  category "Inventory"
  suggested_action "None"
  level "Information"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.load_balancer_name"]
  operators ["=~"]
  alert_when [//]
end

coreo_aws_advisor_alert "elb-old-ssl-policy" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-old-ssl-policy.html"
  display_name "ELB is using old SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is not the latest Amazon predefined SSL policy or is a custom ELB SSL policy."
  category "Security"
  suggested_action "Always use the current AWS predefined security policy."
  level "Critical"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.listener_descriptions.policy_names"]
  operators ["!~"]
  alert_when [/ELBSecurityPolicy-2016-08/i]
end

coreo_aws_advisor_alert "elb-current-ssl-policy" do
  action :define
  service :elb
  display_name "ELB is using current SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is he latest Amazon predefined SSL policy"
  category "Information"
  suggested_action "None."
  level "Information"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.listener_descriptions.policy_names"]
  operators ["=="]
  alert_when ["ELBSecurityPolicy-2016-08"]
end

coreo_aws_advisor_elb "advise-elb" do
  alerts ${AUDIT_AWS_ELB_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_ELB_REGIONS}
end

## This is the normal full notification of the primary recipient.
coreo_uni_util_notify "advise-elb" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_ELB_SEND_ON}"
  payload '{"stack name":"INSTANCE::stack_name",
  "instance name":"INSTANCE::name",
  "number_of_checks":"STACK::coreo_aws_advisor_elb.advise-elb.number_checks",
  "number_of_violations":"STACK::coreo_aws_advisor_elb.advise-elb.number_violations",
  "number_violations_ignored":"STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",
  "violations": STACK::coreo_aws_advisor_elb.advise-elb.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end

## This is part of tag parsing code.
coreo_uni_util_jsrunner "tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
        {
          :name => "tableify",
          :version => "1.0.0"
        }       ])
  json_input '{"stack_name":"INSTANCE::stack_name",
                "instance_name":"INSTANCE::name",
                "violations": STACK::coreo_aws_advisor_elb.advise-elb.report}'
  function <<-EOH
console.log('we are running');
var tableify = require('tableify');
var style_section = "\
<style>body {\
font-family :arial;\
padding : 0px;\
margin : 0px;\
}\
\
table {\
font-size: 10pt;\
border-top : black 1px solid;\
border-right : black 1px solid;\
/* border-spacing : 10px */\
border-collapse : collapse;\
}\
\
td, th {\
text-align : left;\
vertical-align : top;\
white-space: nowrap;\
overflow: hidden;\
text-overflow: ellipsis;\
border-left : black 1px solid;\
border-bottom: black 1px solid;\
padding-left : 4px;\
padding-right : 4px;\
}\
\
th {\
background-color : #aaaaaa;\
}\
\
td.number {\
color : blue\
}\
\
td.boolean {\
color : green;\
font-style : italic;\
}\
\
td.date {\
color : purple;\
}\
\
td.null:after {\
color : gray;\
font-style : italic;\
content : null;\
}\
</style>\
";
payloads = {};
notifiers = [];
results = json_input["violations"];
stack_name = json_input["stack_name"];
instance_name = json_input["instance_name"];
for (elb_id in results) {
  ret_table = "";
  tags_str = "";
  tags = results[elb_id]['tags'];
  for (var i = 0; i < tags.length; i++) {
    this_tag_key = tags[i]['key'];
    tags_str = tags_str + this_tag_key + ", ";
  }
  tags_str = tags_str.replace(/, $/, "");
  found_owner_tag = false;
  owner_tag_val = "${AUDIT_AWS_ELB_ALERT_RECIPIENT}";
  for (var i = 0; i < tags.length; i++) {
    if (tags[i]['key'] === 'bv:nexus:team') {
      found_owner_tag = true;
      owner_tag_val = tags[i]['value'];
    }
  }

  var violation_keys = Object.keys( results[elb_id]["violations"] );
  for (var j = 0, length = violation_keys.length; j < length; j++) {
    this_violation = results[elb_id]["violations"][violation_keys[j]];
    this_rule_name = violation_keys[j];
    region = this_violation["region"];
    aws_console = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#LoadBalancers:search=" + elb_id + "";
    aws_console_html = "<a href=" + aws_console + ">AWS Console</a>";
    ret_table = "";
    ret_table = ret_table + '{"ELB id" : "' + elb_id + '", "region" : "' + region + '", "aws link" : "' + aws_console_html + '","aws tags" : "' + tags_str + '"}';
    if (!payloads.hasOwnProperty(owner_tag_val)) {
      payloads[owner_tag_val] = {};
    }
    if (!payloads[owner_tag_val].hasOwnProperty(this_rule_name)) {
      payloads[owner_tag_val][this_rule_name] = [];
    }
    payloads[owner_tag_val][this_rule_name].push(ret_table);
  }
}

for (email in payloads) {
  nviolations = 0;
  var endpoint = {};
  endpoint['to'] = email;
  var notifier = {};
  notifier['type'] = 'email';
  notifier['send_on'] = 'always';
  notifier['allow_empty'] = 'true';
  notifier['payload_type'] = 'html';
  notifier['endpoint'] = endpoint;
  notifier['payload'] = "";
  notifier['num_violations'] = "";
// tableify goes here
//ret_table = ret_table + "]";
//ret_obj = JSON.parse(ret_table);
//html = tableify(ret_obj);
//html = style_section + html;
// notifier['payload']['stack name'] = json_input['stack name'];
// notifier['payload']['instance name'] = json_input['instance name'];

  html_obj = "";
  var alert_rule_keys = Object.keys( payloads[email] );
  for (var j = 0, length = alert_rule_keys.length; j < length; j++) {
    this_rule_violations = payloads[email][alert_rule_keys[j]];
    this_rule_name = alert_rule_keys[j];

    table_obj = this_rule_violations.join();
    table_obj = "[" + table_obj + "]";
    table_json_obj = JSON.parse(table_obj);
    this_html_obj = "<p>" + this_rule_name + "</p>" + tableify(table_json_obj);
    html_obj = html_obj + this_html_obj;
    nviolations++;
  }
  html_obj = style_section + html_obj;

  notifier['payload'] = html_obj;
  notifier['num_violations'] = nviolations.toString();
  //console.log("gjm: " + notifier['payload']);
  notifiers.push(notifier);
}
callback(notifiers);
EOH
end

# these two jsrunners are for debug purposes only - they send the internal files to you for debugging
#
coreo_uni_util_notify "advise-jsrunner-file" do
  action :notify
  type 'email'
  allow_empty true
  payload_type "text"
  payload 'STACK::coreo_uni_util_jsrunner.tags-to-notifiers-array.jsrunner_file'
  endpoint ({
      :to => 'george@cloudcoreo.com', :subject => 'jsrunner file for INSTANCE::stack_name :: INSTANCE::name'
  })
end
coreo_uni_util_notify "advise-package" do
  action :notify
  type 'email'
  allow_empty true
  payload_type "json"
  payload 'STACK::coreo_uni_util_jsrunner.tags-to-notifiers-array.packages_file'
  endpoint ({
      :to => 'george@cloudcoreo.com', :subject => 'package.json file for INSTANCE::stack_name :: INSTANCE::name'
  })
end

coreo_uni_util_notify "advise-elb-to-tag-values" do
  action :notify
  notifiers 'STACK::coreo_uni_util_jsrunner.tags-to-notifiers-array.return' 
end


#  "number_of_checks":"STACK::coreo_aws_advisor_elb.advise-elb.number_checks",
#  "number_of_violations":"STACK::coreo_aws_advisor_elb.advise-elb.number_violations",
# "number_violations_ignored":"STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",

# This is the summary report of how many alerts were sent to which emails.
coreo_uni_util_jsrunner "tags-rollup" do
  action :run
  data_type "text"
  json_input 'STACK::coreo_uni_util_jsrunner.tags-to-notifiers-array.return'
  #json_input 'STACK::coreo_aws_advisor_elb.advise-elb.report'
  function <<-EOH
//var rollup = [];
var rollup_string = "";
for (var entry=0; entry < json_input.length; entry++) {
  console.log(json_input[entry]);
  if (json_input[entry]['endpoint']['to'].length) {
    console.log('got an email to rollup');
    //nViolations = json_input[entry]['payload']['violations'].length;
    //rollup.push({'recipient': json_input[entry]['endpoint']['to'], 'nViolations': nViolations});
    rollup_string = rollup_string + "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
  }
}
callback(rollup_string);
EOH
end

coreo_uni_util_notify "advise-elb-rollup" do
  action :notify
  type 'email'
  allow_empty true
  send_on 'always'
  payload '
  stack name: INSTANCE::stack_name
  instance name: INSTANCE::name
  number_of_checks: STACK::coreo_aws_advisor_elb.advise-elb.number_checks
  number_of_violations: STACK::coreo_aws_advisor_elb.advise-elb.number_violations
  number_violations_ignored: STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations
  rollup report:
  STACK::coreo_uni_util_jsrunner.tags-rollup.return'
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end


