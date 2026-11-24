# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class ProcessRuleService
      def initialize(policy_configuration:, policy_index:, policy:)
        @policy_configuration = policy_configuration
        @policy_index = policy_index
        @policy = policy
      end

      def execute
        create_new_schedule_rules
      end

      private

      attr_reader :policy_configuration, :policy_index, :policy

      def create_new_schedule_rules
        limit = Gitlab::CurrentSettings.scan_execution_policies_schedule_limit
        limited = limit > 0

        policy[:rules].each_with_index do |rule, rule_index|
          next if rule[:type] != Security::ScanExecutionPolicy::RULE_TYPES[:schedule]
          break if limited && limit == 0

          rule_schedule = Security::OrchestrationPolicyRuleSchedule.new(
            security_orchestration_policy_configuration: policy_configuration,
            policy_index: policy_index,
            rule_index: rule_index,
            cron: rule[:cadence],
            owner: policy_configuration.policy_last_updated_by,
            policy_type: 'scan_execution_policy'
          )

          unless rule_schedule.valid?
            Gitlab::AppLogger.warn(
              message: "Failed to create policy rule schedule: #{rule_schedule.errors.full_messages}",
              policy_configuration_id: policy_configuration.id,
              policy_index: policy_index,
              rule_index: rule_index
            )
            next
          end

          rule_schedule.save!

          limit -= 1
        end
      end
    end
  end
end
