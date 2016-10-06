coreo_aws_advisor_alert "elb-old-ssl-policy" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-old-ssl-policy.html"
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
