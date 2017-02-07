
coreo_aws_rule "elb-inventory" do
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
  raise_when [//]
  id_map "object.load_balancer_descriptions.load_balancer_name"
end

coreo_aws_rule "elb-old-ssl-policy" do
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
  raise_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
  id_map "modifiers.load_balancer_name"
end

coreo_aws_rule "elb-current-ssl-policy" do
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
  raise_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
  id_map "modifiers.load_balancer_name"
end

coreo_aws_rule_runner_elb "advise-elb" do
  rules ${AUDIT_AWS_ELB_ALERT_LIST}
  action :run
  regions ${AUDIT_AWS_ELB_REGIONS}
end

coreo_uni_util_jsrunner "jsrunner-process-suppression-elb" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.report}'
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
  function createViolationWithSuppression(result) {
      const regionKeys = Object.keys(violations);
      regionKeys.forEach(regionKey => {
          result[regionKey] = {};
          const objectIdKeys = Object.keys(violations[regionKey]);
          objectIdKeys.forEach(objectIdKey => {
              createObjectId(regionKey, objectIdKey);
          });
      });
  }
  
  function createObjectId(regionKey, objectIdKey) {
      const wayToResultObjectId = result[regionKey][objectIdKey] = {};
      const wayToViolationObjectId = violations[regionKey][objectIdKey];
      wayToResultObjectId.tags = wayToViolationObjectId.tags;
      wayToResultObjectId.violations = {};
      createSuppression(wayToViolationObjectId, regionKey, objectIdKey);
  }
  
  
  function createSuppression(wayToViolationObjectId, regionKey, violationObjectIdKey) {
      const ruleKeys = Object.keys(wayToViolationObjectId['violations']);
      ruleKeys.forEach(violationRuleKey => {
          result[regionKey][violationObjectIdKey].violations[violationRuleKey] = wayToViolationObjectId['violations'][violationRuleKey];
          Object.keys(suppression).forEach(suppressRuleKey => {
              suppression[suppressRuleKey].forEach(suppressionObject => {
                  Object.keys(suppressionObject).forEach(suppressObjectIdKey => {
                      setDateForSuppression(
                          suppressionObject, suppressObjectIdKey,
                          violationRuleKey, suppressRuleKey,
                          violationObjectIdKey, regionKey
                      );
                  });
              });
          });
      });
  }
  
  
  function setDateForSuppression(
      suppressionObject, suppressObjectIdKey,
      violationRuleKey, suppressRuleKey,
      violationObjectIdKey, regionKey
  ) {
      file_date = null;
      let suppressDate = suppressionObject[suppressObjectIdKey];
      const areViolationsEqual = violationRuleKey === suppressRuleKey && violationObjectIdKey === suppressObjectIdKey;
      if (areViolationsEqual) {
          const nowDate = new Date();
          const correctDateSuppress = getCorrectSuppressDate(suppressDate);
          const isSuppressionDate = nowDate <= correctDateSuppress;
          if (isSuppressionDate) {
              setSuppressionProp(regionKey, violationObjectIdKey, violationRuleKey, file_date);
          } else {
              setSuppressionExpired(regionKey, violationObjectIdKey, violationRuleKey, file_date);
          }
      }
  }
  
  
  function getCorrectSuppressDate(suppressDate) {
      const hasSuppressionDate = suppressDate !== '';
      if (hasSuppressionDate) {
          file_date = suppressDate;
      } else {
          suppressDate = new Date();
      }
      let correctDateSuppress = new Date(suppressDate);
      if (isNaN(correctDateSuppress.getTime())) {
          correctDateSuppress = new Date(0);
      }
      return correctDateSuppress;
  }
  
  
  function setSuppressionProp(regionKey, objectIdKey, violationRuleKey, file_date) {
      const wayToViolationObject = result[regionKey][objectIdKey].violations[violationRuleKey];
      wayToViolationObject["suppressed"] = true;
      if (file_date != null) {
          wayToViolationObject["suppression_until"] = file_date;
          wayToViolationObject["suppression_expired"] = false;
      }
  }
  
  function setSuppressionExpired(regionKey, objectIdKey, violationRuleKey, file_date) {
      if (file_date !== null) {
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_until"] = file_date;
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_expired"] = true;
      } else {
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_expired"] = false;
      }
      result[regionKey][objectIdKey].violations[violationRuleKey]["suppressed"] = false;
  }
  
  const violations = json_input['violations'];
  const result = {};
  createViolationWithSuppression(result, json_input);
  
  
  callback(result);
  EOH
end



coreo_uni_util_variables "elb-for-suppression-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-elb.return'}
            ])
end

coreo_uni_util_jsrunner "jsrunner-process-table-elb" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.report}'
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

coreo_uni_util_jsrunner "jsrunner-process-alert-list-elb" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    let alertListToJSON = "${AUDIT_AWS_RDS_ALERT_LIST}";
    let alertListArray = alertListToJSON.replace(/'/g, '"');
    callback(alertListArray);
  EOH
end

coreo_uni_util_jsrunner "elb-tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.7.8"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "alert list": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-alert-list-elb.return,
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
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb rule results on PLAN::stack_name :: PLAN::name'
  })
end


