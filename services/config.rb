
coreo_aws_advisor_alert "elb-inventory" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "ELB Object Inventory"
  description "This rule performs an inventory on all Classic ELB's in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.load_balancer_name"]
  operators ["=~"]
  alert_when [//]
  id_map "object.load_balancer_descriptions.load_balancer_name"
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
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "!~"]
  alert_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
  id_map "modifiers.load_balancer_name"
end

coreo_aws_advisor_alert "elb-current-ssl-policy" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-current-ssl-policy.html"
  include_violations_in_count false
  display_name "ELB is using current SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is the latest Amazon predefined SSL policy"
  category "Informational"
  suggested_action "None."
  level "Informational"
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "=~"]
  alert_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
  id_map "modifiers.load_balancer_name"
end

coreo_aws_advisor_elb "advise-elb" do
  alerts ${AUDIT_AWS_ELB_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_ELB_REGIONS}
end

coreo_uni_util_jsrunner "jsrunner-process-suppression-elb" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_advisor_elb.advise-elb.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
  const fs = require('fs');
  const yaml = require('js-yaml');
  let suppression;
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
  }
  coreoExport('suppression', JSON.stringify(suppression));
  const violations = json_input.violations;
  const result = {};
  let file_date = null;
  const regionKeys = Object.keys(violations);
  regionKeys.forEach(region => {
      result[region] = {};
      const violationKeys = Object.keys(violations[region]);
      violationKeys.forEach(violator_id => {
          result[region][violator_id] = {};
          result[region][violator_id].tags = violations[region][violator_id].tags;
          result[region][violator_id].violations = {};
          const ruleKeys = Object.keys(violations[region][violator_id].violations);
          ruleKeys.forEach(rule_id => {
              let is_violation = true;
              result[region][violator_id].violations[rule_id] = violations[region][violator_id].violations[rule_id];
              const suppressionRuleKeys = Object.keys(suppression);
              suppressionRuleKeys.forEach(suppress_rule_id => {
                  const suppressionViolatorNum = Object.keys(suppression[suppress_rule_id]);
                  suppressionViolatorNum.forEach(suppress_violator_num => {
                      const suppressViolatorIdKeys = Object.keys(suppression[suppress_rule_id][suppress_violator_num]);
                      suppressViolatorIdKeys.forEach(suppress_violator_id => {
                          file_date = null;
                          let suppress_obj_id_time = suppression[suppress_rule_id][suppress_violator_num][suppress_violator_id];
                          if (rule_id === suppress_rule_id) {
  
                              if (violator_id === suppress_violator_id) {
                                  const now_date = new Date();
  
                                  if (suppress_obj_id_time === "") {
                                      suppress_obj_id_time = new Date();
                                  } else {
                                      file_date = suppress_obj_id_time;
                                      suppress_obj_id_time = file_date;
                                  }
                                  let rule_date = new Date(suppress_obj_id_time);
                                  if (isNaN(rule_date.getTime())) {
                                      rule_date = new Date(0);
                                  }
  
                                  if (now_date <= rule_date) {
  
                                      is_violation = false;
  
                                      result[region][violator_id].violations[rule_id]["suppressed"] = true;
                                      if (file_date != null) {
                                          result[region][violator_id].violations[rule_id]["suppressed_until"] = file_date;
                                          result[region][violator_id].violations[rule_id]["suppression_expired"] = false;
                                      }
                                  }
                              }
                          }
                      });
                  });
              });
              if (is_violation) {
  
                  if (file_date !== null) {
                      result[region][violator_id].violations[rule_id]["suppressed_until"] = file_date;
                      result[region][violator_id].violations[rule_id]["suppression_expired"] = true;
                  } else {
                      result[region][violator_id].violations[rule_id]["suppression_expired"] = false;
                  }
                  result[region][violator_id].violations[rule_id]["suppressed"] = false;
              }
          });
      });
  });
  
  
  callback(result);
  EOH
end

coreo_uni_util_variables "elb-for-suppression-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_advisor_elb.advise-elb.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-elb.return'}
            ])
end

coreo_uni_util_jsrunner "jsrunner-process-table-elb" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_advisor_elb.advise-elb.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');
    try {
        var table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
    } catch (e) {
    }
    coreoExport('table', JSON.stringify(table));
    callback(table);
  EOH
end

coreo_uni_util_jsrunner "elb-tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "table": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-table-elb.return,
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-elb.return}'
  function <<-EOH
  

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_ELB_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_ELB_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_ELB_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_ELB_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG,
     ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditELB = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES);
const notifiers = AuditELB.getNotifiers();
callback(notifiers);
  EOH
end

coreo_uni_util_jsrunner "elb-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.return'
  function <<-EOH
var rollup_string = "";
let rollup = '';
let emailText = '';
let numberOfViolations = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "Violations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += 'Rollup' + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
  EOH
end

coreo_uni_util_notify "advise-elb-to-tag-values" do
  action :${AUDIT_AWS_ELB_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-elb-rollup" do
  action :${AUDIT_AWS_ELB_ROLLUP_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_ELB_SEND_ON}"
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.elb-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end


