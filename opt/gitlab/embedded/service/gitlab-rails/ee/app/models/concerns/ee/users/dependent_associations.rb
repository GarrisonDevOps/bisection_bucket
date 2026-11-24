# frozen_string_literal: true

module EE
  module Users
    module DependentAssociations
      extend ActiveSupport::Concern

      included do
        # rubocop:disable Cop/ActiveRecordDependent -- we need to destroy/nullify records after each user delete.
        has_many :ai_user_metrics,
          foreign_key: :user_id,
          class_name: 'Ai::UserMetrics',
          inverse_of: :user,
          dependent: :destroy

        has_many :board_assignees,
          foreign_key: :assignee_id,
          class_name: 'BoardAssignee',
          inverse_of: :assignee,
          dependent: :destroy

        has_many :merge_requests_approval_rules_approver_users,
          class_name: 'MergeRequests::ApprovalRulesApproverUser',
          dependent: :destroy

        has_many :approval_group_rules_users, class_name: 'ApprovalRules::ApprovalGroupRulesUser', dependent: :destroy

        has_many :approval_merge_request_rules_approved_approvers,
          class_name: 'ApprovalRules::ApprovalMergeRequestRulesApprovedApprover',
          foreign_key: :user_id,
          inverse_of: :user,
          dependent: :destroy

        has_many :approval_merge_request_rules_users, dependent: :destroy

        has_many :approval_project_rules_users, dependent: :destroy

        has_many :lists, dependent: :destroy

        has_many :security_policy_dismissals,
          class_name: 'Security::PolicyDismissal',
          dependent: :nullify

        has_many :targeted_message_dismissals,
          class_name: 'Notifications::TargetedMessageDismissal',
          dependent: :destroy

        has_many :boards_epic_list_user_preferences,
          class_name: 'Boards::EpicListUserPreference',
          dependent: :destroy

        has_many :security_orchestration_policy_rule_schedules,
          class_name: 'Security::OrchestrationPolicyRuleSchedule',
          inverse_of: :owner,
          dependent: :destroy

        has_many :approval_policy_merge_request_bypass_events,
          class_name: 'Security::ApprovalPolicyMergeRequestBypassEvent',
          inverse_of: :user,
          dependent: :nullify

        has_many :duo_workflows_workflows,
          class_name: 'Ai::DuoWorkflows::Workflow',
          dependent: :destroy

        has_many :created_custom_fields,
          class_name: 'Issuables::CustomField',
          foreign_key: 'created_by_id',
          dependent: :nullify,
          inverse_of: :created_by

        has_many :updated_custom_fields,
          class_name: 'Issuables::CustomField',
          foreign_key: 'updated_by_id',
          dependent: :nullify,
          inverse_of: :updated_by

        has_many :created_lifecycles,
          class_name: 'WorkItems::Statuses::Custom::Lifecycle',
          foreign_key: 'created_by_id',
          dependent: :nullify,
          inverse_of: :created_by

        has_many :updated_lifecycles,
          class_name: 'WorkItems::Statuses::Custom::Lifecycle',
          foreign_key: 'updated_by_id',
          dependent: :nullify,
          inverse_of: :updated_by

        has_many :created_statuses,
          class_name: 'WorkItems::Statuses::Custom::Status',
          foreign_key: 'created_by_id',
          dependent: :nullify,
          inverse_of: :created_by

        has_many :updated_statuses,
          class_name: 'WorkItems::Statuses::Custom::Status',
          foreign_key: 'updated_by_id',
          dependent: :nullify,
          inverse_of: :updated_by
        # rubocop:enable Cop/ActiveRecordDependent -- we need to destroy/nullify records after each user delete.
      end
    end
  end
end
