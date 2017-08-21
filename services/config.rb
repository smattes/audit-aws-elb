
coreo_aws_rule "elb-inventory" do
  action :define
  service :ElasticLoadBalancing
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ELB Object Inventory"
  description "This rule performs an inventory on all Classic ELB's in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["load_balancers"]
  audit_objects ["object.load_balancer_descriptions.load_balancer_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.load_balancer_descriptions.load_balancer_name"
end

coreo_aws_rule "elb-load-balancers-active-security-groups-list" do
  action :define
  service :ElasticLoadBalancing
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["load_balancers"]
  audit_objects ["object.load_balancer_descriptions.security_groups"]
  operators ["=~"]
  raise_when [//]
  id_map "object.load_balancer_descriptions.load_balancer_name"
end

coreo_aws_rule "elb-old-ssl-policy" do
  action :define
  service :ElasticLoadBalancing
  link "http://kb.cloudcoreo.com/mydoc_elb-old-ssl-policy.html"
  display_name "ELB is using old SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is not the latest Amazon predefined SSL policy or is a custom ELB SSL policy."
  category "Security"
  suggested_action "Always use the current AWS predefined security policy."
  level "High"
  meta_nist_171_id "3.5.4"
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "object.policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "!~"]
  raise_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
  id_map "modifiers.load_balancer_name"
end

coreo_aws_rule "elb-current-ssl-policy" do
  action :define
  service :ElasticLoadBalancing
  link "http://kb.cloudcoreo.com/mydoc_elb-current-ssl-policy.html"
  include_violations_in_count false
  display_name "ELB is using current SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is the latest Amazon predefined SSL policy"
  category "Informational"
  suggested_action "None."
  level "Informational"
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "object.policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "=~"]
  raise_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
  id_map "modifiers.load_balancer_name"
end
git checkout -b CON-200-audit-objects-must-be-prefixed-with-object-var
git add .
git commit -m "CON-200 prefixed 'object' to audit_objects"
git push origin CON-200-audit-objects-must-be-prefixed-with-object-var

coreo_uni_util_variables "elb-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.results' => 'unset'},
                {'GLOBAL::number_violations' => '0'}
            ])
end

coreo_aws_rule_runner "advise-elb" do
  rules ${AUDIT_AWS_ELB_ALERT_LIST}
  service :ElasticLoadBalancing
  action :run
  regions ${AUDIT_AWS_ELB_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_uni_util_variables "elb-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-elb.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-elb.number_violations'},

            ])
end

coreo_uni_util_jsrunner "elb-tags-to-notifiers-array" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-beta64"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "compositeName":"PLAN::stack_name",
                "planName":"PLAN::name",
                "teamName":"PLAN::team_name",
                "cloudAccountName": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-elb.report}'
  function <<-EOH

const compositeName = json_input.compositeName;
const planName = json_input.planName;
const cloudAccount = json_input.cloudAccountName;
const cloudObjects = json_input.violations;
const teamName = json_input.teamName;

const NO_OWNER_EMAIL = "${AUDIT_AWS_ELB_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_ELB_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_ELB_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_ELB_SEND_ON}";
const htmlReportSubject = "${HTML_REPORT_SUBJECT}";

const alertListArray = ${AUDIT_AWS_ELB_ALERT_LIST};
const ruleInputs = {};

let userSuppression;
let userSchemes;

const fs = require('fs');
const yaml = require('js-yaml');

function setSuppression() {
  try {
      userSuppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in suppression.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSuppression=[];
    }
  }

  coreoExport('suppression', JSON.stringify(userSuppression));
}

function setTable() {
  try {
    userSchemes = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in table.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSchemes={};
    }
  }

  coreoExport('table', JSON.stringify(userSchemes));
}
setSuppression();
setTable();

const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, userSuppression, OWNER_TAG,
    userSchemes, alertListArray, ruleInputs, ALLOW_EMPTY,
    SEND_ON, cloudAccount, compositeName, planName, htmlReportSubject, teamName
}


function createConfig(argForConfig) {
    let JSON_INPUT = {
        compositeName: argForConfig.compositeName,
        htmlReportSubject: argForConfig.htmlReportSubject,
        planName: argForConfig.planName,
        teamName: argForConfig.teamName,
        violations: argForConfig.cloudObjects,
        userSchemes: argForConfig.userSchemes,
        userSuppression: argForConfig.userSuppression,
        alertList: argForConfig.alertListArray,
        disabled: argForConfig.ruleInputs,
        cloudAccount: argForConfig.cloudAccount
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
const suppressionJSON = CloudCoreoJSRunner.createJSONWithSuppress(JSON_INPUT, SETTINGS);

coreoExport('JSONReport', JSON.stringify(suppressionJSON));
coreoExport('report', JSON.stringify(suppressionJSON['violations']));

callback(emails);
  EOH
end

coreo_uni_util_variables "elb-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.JSONReport'},{'COMPOSITE::coreo_aws_rule_runner.advise-elb.report' => 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.report'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.table'}
            ])
end

coreo_uni_util_jsrunner "elb-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    let usedEmails=new Map();
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        const email = notifier['endpoint']['to'];
        if(hasEmail && usedEmails.get(email)!==true) {
            usedEmails.set(email,true);
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['numberOfViolatingCloudObjects'] + ", Cloud Objects: "+ (notifier["num_violations"]-notifier['numberOfViolatingCloudObjects']) + "\\n";
        }
    });

    textRollup += 'Total Number of matching Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;

}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-elb-to-tag-values" do
  action((("${AUDIT_AWS_ELB_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-elb-rollup" do
  action((("${AUDIT_AWS_ELB_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_ELB_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_ELB_SEND_ON}"
  payload '
COMPOSITE::coreo_uni_util_jsrunner.elb-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo full rollup report for elb rule results on PLAN::stack_name :: PLAN::name'
  })
end

coreo_aws_s3_policy "cloudcoreo-audit-aws-elb-policy" do
  action((("${AUDIT_AWS_ELB_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  policy_document <<-EOF
{
"Version": "2012-10-17",
"Statement": [
{
"Sid": "",
"Effect": "Allow",
"Principal":
{ "AWS": "*" }
,
"Action": "s3:*",
"Resource": [
"arn:aws:s3:::${AUDIT_AWS_ELB_S3_NOTIFICATION_BUCKET_NAME}/*",
"arn:aws:s3:::${AUDIT_AWS_ELB_S3_NOTIFICATION_BUCKET_NAME}"
]
}
]
}
  EOF
end

coreo_aws_s3_bucket "bucket-${AUDIT_AWS_ELB_S3_NOTIFICATION_BUCKET_NAME}" do
  action((("${AUDIT_AWS_ELB_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  bucket_policies ["cloudcoreo-audit-aws-elb-policy"]
end

coreo_uni_util_notify "cloudcoreo-audit-aws-elb-s3" do
  action((("${AUDIT_AWS_ELB_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :notify : :nothing)
  type 's3'
  allow_empty true
  payload 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.report'
  endpoint ({
      object_name: 'aws-elb-json',
      bucket_name: '${AUDIT_AWS_ELB_S3_NOTIFICATION_BUCKET_NAME}',
      folder: 'elb/PLAN::name',
      properties: {}
  })
end
