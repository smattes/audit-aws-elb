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

coreo_aws_advisor_elb "advise-elb" do
  alerts ${AUDIT_AWS_ELB_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_ELB_REGIONS}
end

## This is the normal full notification of the primary recipient.
# coreo_uni_util_notify "advise-elb" do
#   action :notify
#   type 'email'
#   allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
#   send_on "${AUDIT_AWS_ELB_SEND_ON}"
#   payload '{"stack name":"INSTANCE::stack_name",
#   "instance name":"INSTANCE::name",
#   "number_of_checks":"STACK::coreo_aws_advisor_elb.advise-elb.number_checks",
#   "number_of_violations":"STACK::coreo_aws_advisor_elb.advise-elb.number_violations",
#   "number_violations_ignored":"STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",
#   "violations": STACK::coreo_aws_advisor_elb.advise-elb.report }'
#   payload_type "json"
#   endpoint ({
#       :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
#   })
# end

## This is part of tag parsing code.
coreo_uni_util_jsrunner "tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
        {
          :name => "tableify",
          :version => "1.0.0"
        }       ])
  json_input '{"stack name":"INSTANCE::stack_name",
                "instance name":"INSTANCE::name",
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
violations=json_input["violations"];
for (instance_id in violations) {
  ret_table = "[";
  inst_tags_string = "";
  tags_str = "";
  tags = violations[instance_id]['tags'];
  for (var i = 0; i < tags.length; i++) {
    this_tag_key = tags[i]['key'];
    tags_str = tags_str + this_tag_key + ", ";
  }
  tags_str = tags_str.replace(/, $/, "");
  for (var i = 0; i < tags.length; i++) {
    if (tags[i]['key'] === 'bv:nexus:team') {
      var aalert = {};
      aalert[instance_id] = violations[instance_id];
      region = violations[instance_id]["violations"]["elb-old-ssl-policy"]["region"];
      aws_console = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#LoadBalancers:search=" + instance_id + "";
      aws_console_html = "<a href=" + aws_console + ">AWS Console</a>";
      ret_table = ret_table + '{"ELB id" : "' + instance_id + '", "region" : "' + region + '", "aws link" : "' + aws_console_html + '","aws tags" : "' + tags_str + '"}, ';
      ret_table = ret_table.replace(/, $/, "");
      ret_table = ret_table + "]";
      ret_obj = JSON.parse(ret_table);
      html = tableify(ret_obj);
      tagVal = tags[i]['value'];
      if (!payloads.hasOwnProperty(tagVal)) {
        payloads[tagVal] = [];
      }
      payloads[tagVal].push(html);
    }
  }
}
for (email in payloads) {
  var endpoint = {};
  endpoint['to'] = email;
  var notifier = {};
  notifier['type'] = 'email';
  notifier['send_on'] = 'always';
  notifier['allow_empty'] = 'true';
  notifier['payload_type'] = 'json';
  notifier['endpoint'] = endpoint;
  notifier['payload'] = {};
  notifier['payload']['stack name'] = json_input['stack name'];
  notifier['payload']['instance name'] = json_input['instance name'];
  notifier['payload']['violations'] = payloads[email];
  notifiers.push(notifier);
}
callback(notifiers);
EOH
end

 coreo_uni_util_notify "advise-elb-to-tag-values" do
   action :notify
   notifiers 'STACK::coreo_uni_util_jsrunner.tags-to-notifiers-array.return' 
 end


#  "number_of_checks":"STACK::coreo_aws_advisor_elb.advise-elb.number_checks",
#  "number_of_violations":"STACK::coreo_aws_advisor_elb.advise-elb.number_violations",
# "number_violations_ignored":"STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",

## This is the summary report of how many alerts were sent to which emails.
# coreo_uni_util_jsrunner "tags-rollup" do
#   action :run
#   data_type "text"
#   #json_input 'STACK::coreo_uni_util_jsrunner.tags-to-notifiers-array.return'
#   json_input 'STACK::coreo_aws_advisor_elb.advise-elb.report'
#   function <<-EOH
# var rollup = [];
# for (var entry=0; entry < json_input.length; entry++) {
#   console.log(json_input[entry]);
#   if (json_input[entry]['endpoint']['to'].length) {
#     console.log('got an email to rollup');
#     nViolations = json_input[entry]['payload']['violations'].length;
#     rollup.push({'recipient': json_input[entry]['endpoint']['to'], 'nViolations': nViolations});
#   }
# }
# callback(rollup);
# EOH
# end

# coreo_uni_util_notify "advise-elb-rollup" do
#   action :notify
#   type 'email'
#   allow_empty true
#   send_on 'always'
#   payload '"stack name":"INSTANCE::stack_name\\n",
#   "instance name":"INSTANCE::name\\n",
#   "number_of_checks":"STACK::coreo_aws_advisor_elb.advise-elb.number_checks\\n",
#   "number_of_violations":"STACK::coreo_aws_advisor_elb.advise-elb.number_violations\\n",
#   "number_violations_ignored":"STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations\\n",
#   "rollup report": \\n\\n STACK::coreo_uni_util_jsrunner.tags-rollup.return'
#   payload_type 'text'
#   endpoint ({
#       :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
#   })
# end


