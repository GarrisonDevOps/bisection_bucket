# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module ApprovalRules
      class CreateService < BaseService
        include Gitlab::InternalEventsTracking

        def execute
          approval_policy_rules.each do |approval_policy_rule|
            if approval_actions.blank?
              create_rule(approval_policy_rule)
              next
            end

            approval_actions.each_with_index do |approval_action, action_index|
              create_rule(approval_policy_rule, action_index, approval_action)
            end
          end

          track_multiple_approval_actions
        end

        private

        def create_approval_rule?(rule)
          return true unless rule.type_any_merge_request?

          # For `any_merge_request` rules, the approval rules can be created without approvers and can override
          # project approval settings in general.
          # The violations in this case are handled via SyncAnyMergeRequestRulesService
          approval_actions.present?
        end

        def create_rule(approval_policy_rule, action_index = 0, approval_action = nil)
          approval_rule = project_approval_rules_map.dig(approval_policy_rule.id, action_index)

          return if approval_rule.present?

          scan_result_policy_read =
            find_or_create_scan_result_policy(approval_policy_rule, action_index, approval_action)

          return unless create_approval_rule?(approval_policy_rule)

          sync_license_scanning_rule(approval_policy_rule, scan_result_policy_read)

          result = ::ApprovalRules::CreateService.new(
            project, author, rule_params(approval_policy_rule, scan_result_policy_read, action_index, approval_action)
          ).execute

          if result.success?
            track_approval_rule_creation(approval_policy_rule.type)
            return
          end

          log_service_failure(
            'approval_rule_creation_failed', approval_policy_rule, scan_result_policy_read,
            action_index, result.errors)
        end

        # A read left behind by an interrupted delete has no approval_project_rule. Returning early on it
        # (as before) meant the rule was never recreated, so refresh and reuse it instead.
        # See https://gitlab.com/gitlab-org/gitlab/-/issues/625031
        def find_or_create_scan_result_policy(approval_policy_rule, action_index, approval_action)
          existing_read = scan_result_policy_reads_map.dig(approval_policy_rule.id, action_index)
          return create_scan_result_policy(approval_policy_rule, action_index, approval_action) unless existing_read

          existing_read.update!(scan_result_policy_read_params(approval_policy_rule, action_index, approval_action))
          existing_read
        end

        def create_scan_result_policy(approval_policy_rule, action_index = 0, approval_action = nil)
          security_policy.security_orchestration_policy_configuration.scan_result_policy_reads.create!(
            scan_result_policy_read_params(approval_policy_rule, action_index, approval_action)
          )
        end

        def track_multiple_approval_actions
          return unless approval_actions.present? && approval_actions.size > 1

          track_internal_event('check_multiple_approval_actions_for_approval_policy', project: project)
        end

        def track_approval_rule_creation(rule_type)
          track_internal_event(
            'create_approval_rule_from_merge_request_approval_policy',
            project: project,
            additional_properties: {
              label: rule_type, # Type of the Merge Request Approval Policy
              enforcement_type: security_policy.enforcement_type
            }
          )
        end
      end
    end
  end
end
