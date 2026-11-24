# frozen_string_literal: true

module Security
  class ScanResultPolicyRead < ApplicationRecord
    include ::Gitlab::Utils::StrongMemoize
    include ::GitlabSubscriptions::SubscriptionHelper

    self.table_name = 'scan_result_policies'

    FALLBACK_BEHAVIORS = {
      open: "open",
      closed: "closed"
    }.freeze

    alias_attribute :match_on_inclusion_license, :match_on_inclusion

    enum :age_operator, { greater_than: 0, less_than: 1 }
    enum :age_interval, { day: 0, week: 1, month: 2, year: 3 }
    enum :commits, { any: 0, unsigned: 1 }, prefix: true

    belongs_to :security_orchestration_policy_configuration, class_name: 'Security::OrchestrationPolicyConfiguration'
    belongs_to :project, optional: true
    belongs_to :approval_policy_rule, optional: true, class_name: 'Security::ApprovalPolicyRule'
    has_many :software_license_policies
    has_many :approval_merge_request_rules, foreign_key: 'scan_result_policy_id', inverse_of: :scan_result_policy_read
    has_many :violations, foreign_key: 'scan_result_policy_id', class_name: 'Security::ScanResultPolicyViolation',
      inverse_of: :scan_result_policy_read

    validates :match_on_inclusion_license, inclusion: { in: [true, false], message: 'must be a boolean value' }
    validates :role_approvers, inclusion: { in: Gitlab::Access.all_values }
    validates :age_value, numericality: { only_integer: true, greater_than_or_equal_to: 0 }, allow_nil: true
    validates :vulnerability_attributes, json_schema: { filename: 'scan_result_policy_vulnerability_attributes' },
      allow_blank: true
    validates :rule_idx,
      uniqueness: {
        scope: %i[security_orchestration_policy_configuration_id project_id orchestration_policy_idx action_idx]
      },
      numericality: { only_integer: true, greater_than_or_equal_to: 0 }, allow_nil: true
    validates :project_approval_settings, json_schema: { filename: 'scan_result_policy_project_approval_settings' },
      allow_blank: true
    validates :send_bot_message, json_schema: { filename: 'approval_policies_send_bot_message_action' },
      allow_blank: true
    validates :fallback_behavior, json_schema: { filename: 'approval_policies_fallback_behavior' },
      allow_blank: true
    validates :policy_tuning, json_schema: { filename: 'approval_policies_policy_tuning' }
    validates :licenses, json_schema: { filename: 'approval_policies_licenses' }, allow_blank: true

    scope :for_project, ->(project) { where(project: project) }
    scope :for_policy_configuration, ->(policy_configuration) {
      where(security_orchestration_policy_configuration: policy_configuration)
    }
    scope :for_approval_policy_rules, ->(approval_policy_rules) {
      where(approval_policy_rule: approval_policy_rules)
    }
    scope :for_policy_index, ->(policy_index) { where(orchestration_policy_idx: policy_index) }
    scope :with_stale_policy_index, -> do
      joins(approval_policy_rule: :security_policy)
        .where('scan_result_policies.orchestration_policy_idx <> security_policies.policy_index')
        .select('scan_result_policies.*', 'security_policies.policy_index AS current_policy_index')
    end
    # NO KEY UPDATE serialises realigns without blocking FK checks of MR syncs inserting rules for these reads.
    scope :locked_for_realign, -> { lock('FOR NO KEY UPDATE OF scan_result_policies') }
    scope :targeting_commits, -> { where.not(commits: nil) }
    scope :preload_approval_policy_rule, -> { preload(:approval_policy_rule) }
    scope :blocking_branch_modification, -> do
      where("project_approval_settings->>'block_branch_modification' = 'true'")
    end
    scope :prevent_pushing_and_force_pushing, -> do
      where("project_approval_settings->>'prevent_pushing_and_force_pushing' = 'true'")
    end

    def fail_open?
      fallback_behavior["fail"] == FALLBACK_BEHAVIORS[:open]
    end

    def unblock_rules_using_execution_policies?
      policy_tuning['unblock_rules_using_execution_policies'] || false
    end

    def newly_detected?
      license_states.include?(ApprovalProjectRule::NEWLY_DETECTED)
    end

    def only_newly_detected_licenses?
      license_states == [ApprovalProjectRule::NEWLY_DETECTED]
    end

    def vulnerability_age
      return {} unless age_operator.present? && age_interval.present? && age_value.present?

      { operator: age_operator.to_sym, interval: age_interval.to_sym, value: age_value }
    end

    def bot_message_disabled?
      send_bot_message['enabled'] == false
    end

    def bot_message_internal?
      send_bot_message['visibility'] == 'internal'
    end

    def approval_policy_rule
      return super if approval_policy_rule_id.present?
      return if real_policy_index < 0

      Security::ApprovalPolicyRule.by_policy_rule_index(
        security_orchestration_policy_configuration, policy_index: real_policy_index, rule_index: rule_idx
      )
    end
    strong_memoize_attr :approval_policy_rule

    def real_policy_index
      real_index = -1
      active_policy_index = 0
      policies = security_orchestration_policy_configuration.security_policies.type_approval_policy.order_by_index

      policies.each_with_index do |policy, index|
        next unless policy.enabled? && policy.scope_applicable?(project)

        if active_policy_index == orchestration_policy_idx
          real_index = index
          break
        end

        active_policy_index += 1
      end

      real_index
    end
    strong_memoize_attr :real_policy_index

    def custom_role_ids_with_permission
      member_roles = if gitlab_com_subscription?
                       project.root_ancestor.member_roles.id_in(custom_roles)
                     else
                       MemberRole.for_instance.id_in(custom_roles)
                     end

      member_roles.permissions_where(admin_merge_request: true)
                  .or(member_roles.where(base_access_level: Gitlab::Access::DEVELOPER..))
                  .pluck_primary_key
    end

    def prevent_approval_by_author?
      has_approval_setting?("prevent_approval_by_author")
    end

    def prevent_approval_by_commit_author?
      has_approval_setting?("prevent_approval_by_commit_author")
    end

    private

    def has_approval_setting?(key)
      project_approval_settings.fetch(key, false)
    end
  end
end
