# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module ApprovalRules
      class UpdateService < BaseService
        def execute
          approval_policy_rules.each do |approval_policy_rule|
            if approval_actions.blank?
              update_rule(approval_policy_rule)
              next
            end

            approval_actions.each_with_index do |approval_action, action_index|
              update_rule(approval_policy_rule, action_index, approval_action)
            end
          end
        end

        private

        def update_rule(approval_policy_rule, action_index = 0, approval_action = nil)
          scan_result_policy_read = scan_result_policy_reads_map.dig(approval_policy_rule.id, action_index)
          return if scan_result_policy_read.blank? # A concurrent unlink operation may have taken place

          update_scan_result_policy_read(approval_policy_rule, scan_result_policy_read, action_index, approval_action)

          sync_license_scanning_rule(approval_policy_rule, scan_result_policy_read)

          approval_rule = project_approval_rules_map.dig(approval_policy_rule.id, action_index)

          return if approval_rule.blank?

          result = ::ApprovalRules::UpdateService.new(approval_rule, author,
            rule_params(approval_policy_rule, scan_result_policy_read, action_index, approval_action)
          ).execute

          return if result.success?

          log_service_failure(
            'approval_rule_updation_failed', approval_policy_rule, scan_result_policy_read,
            action_index, result.errors)
        end

        def update_scan_result_policy_read(
          approval_policy_rule, scan_result_policy_read, action_index = 0,
          approval_action = nil)
          scan_result_policy_read.update!(
            scan_result_policy_read_params(approval_policy_rule, action_index, approval_action)
          )
        end
      end
    end
  end
end
