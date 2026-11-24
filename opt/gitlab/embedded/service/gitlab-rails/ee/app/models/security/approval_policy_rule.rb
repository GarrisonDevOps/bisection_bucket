# frozen_string_literal: true

module Security
  class ApprovalPolicyRule < ApplicationRecord
    include PolicyRule
    include ::Gitlab::Utils::StrongMemoize
    include ::GitlabSubscriptions::SubscriptionHelper

    self.table_name = 'approval_policy_rules'

    enum :type, { scan_finding: 0, license_finding: 1, any_merge_request: 2 }, prefix: true

    belongs_to :security_policy, class_name: 'Security::Policy', inverse_of: :approval_policy_rules
    belongs_to :security_policy_management_project, class_name: 'Project'

    has_many :approval_policy_rule_project_links, class_name: 'Security::ApprovalPolicyRuleProjectLink'
    has_many :projects, through: :approval_policy_rule_project_links
    has_many :software_license_policies
    has_many :approval_merge_request_rules
    has_many :violations, class_name: 'Security::ScanResultPolicyViolation'

    validates :typed_content, json_schema: { filename: "approval_policy_rule_content", size_limit: 1.megabyte }
    validate :license_override_purls_are_valid, if: :type_license_finding?

    scope :targeting_commits, -> do
      type_any_merge_request.where("approval_policy_rules.content->>'commits' IS NOT NULL")
    end

    scope :including_approval_merge_request_rules, -> { includes(:approval_merge_request_rules) }

    scope :license_finding_with_overrides_for_project, ->(project_id) do
      joins(:approval_policy_rule_project_links)
        .where(approval_policy_rule_project_links: { project_id: project_id })
        .where(type: types[:license_finding])
        .where("content ? 'license_overrides' AND jsonb_array_length(content->'license_overrides') > 0")
    end

    scope :with_enrichment_filters, -> do
      undeleted.where(
        "approval_policy_rules.content->'vulnerability_attributes'->>'known_exploited' IS NOT NULL OR " \
          "approval_policy_rules.content->'vulnerability_attributes'->'epss_score' IS NOT NULL"
      )
    end

    def self.by_policy_rule_index(policy_configuration, policy_index:, rule_index:)
      joins(:security_policy).find_by(
        rule_index: rule_index,
        security_policy: {
          security_orchestration_policy_configuration_id: policy_configuration.id,
          policy_index: policy_index
        }
      )
    end

    def licenses
      typed_content['licenses']
    end

    def license_states
      typed_content['license_states']
    end

    def license_types
      typed_content['license_types']
    end

    def license_overrides
      typed_content['license_overrides'] || []
    end

    def rule
      Security::ScanResultPolicies::Rule.new(content&.deep_symbolize_keys)
    end
    strong_memoize_attr :rule

    delegate :newly_detected?, :only_newly_detected_licenses?, :commits_any?, :commits_unsigned?,
      :vulnerability_age, :vulnerability_attributes, :match_on_inclusion_license, to: :rule

    # The policy can be deleted while a worker still holds the rule; treat that as false instead of raising.
    def fail_open?
      !!approval_policy&.fail_open?
    end

    def bot_message_disabled?
      !!approval_policy&.bot_message_disabled?
    end

    def bot_message_internal?
      !!approval_policy&.bot_message_internal?
    end

    def unblock_rules_using_execution_policies?
      !!approval_policy&.unblock_rules_using_execution_policies?
    end

    def prevent_approval_by_author?
      !!approval_policy&.prevent_approval_by_author?
    end

    def prevent_approval_by_commit_author?
      !!approval_policy&.prevent_approval_by_commit_author?
    end

    delegate :approval_settings, to: :approval_policy, allow_nil: true

    def role_approvers(action_idx:)
      roles_map = ::Gitlab::Access.sym_options_with_owner
      raw_role_approvers(action_idx)
        .filter_map { |role| roles_map[role.to_sym] if role.to_s.in?(Security::ScanResultPolicy::ALLOWED_ROLES) }
    end

    def custom_roles(action_idx:)
      raw_role_approvers(action_idx).select { |role| role.is_a?(Integer) }
    end

    def custom_role_ids_with_permission(project:, action_idx:)
      return [] unless project

      role_ids = custom_roles(action_idx: action_idx)
      member_roles = if gitlab_com_subscription?
                       project.root_ancestor.member_roles.id_in(role_ids)
                     else
                       MemberRole.for_instance.id_in(role_ids)
                     end

      member_roles.permissions_where(admin_merge_request: true)
                  .or(member_roles.where(base_access_level: Gitlab::Access::DEVELOPER..))
                  .pluck_primary_key
    end

    def approval_policy
      security_policy&.approval_policy
    end

    def policy_applies_to_target_branch?(target_branch, project)
      branches, branch_type = content.values_at("branches", "branch_type")

      return branches_apply_to_target_branch?(target_branch, branches) if branches

      branch_type_applies_to_target_branch?(target_branch, branch_type, project)
    end

    def branches_exempted_by_policy?(source_branch, target_branch)
      # `security_policy` can be nil if the parent policy was deleted while this
      # rule still exists (e.g. between policy resync and merge-request approval
      # evaluation). Treat as no exemption rather than crashing the caller.
      return false if security_policy.nil?

      branch_exceptions = security_policy.policy_content.dig(:bypass_settings, :branches)
      return false if branch_exceptions.blank?

      branch_exceptions.any? do |branch_exception|
        source_branch_exception = branch_exception[:source]
        target_branch_exception = branch_exception[:target]

        branch_matches_exception?(source_branch, source_branch_exception) &&
          branch_matches_exception?(target_branch, target_branch_exception)
      end
    end

    private

    def raw_role_approvers(action_idx)
      require_approval_action = approval_policy.actions.require_approval_actions[action_idx]
      require_approval_action&.role_approvers || []
    end

    def branches_apply_to_target_branch?(target_branch, branches)
      return true if branches == []

      branches.any? do |pattern|
        RefMatcher.new(pattern).matches?(target_branch)
      end
    end

    def branch_type_applies_to_target_branch?(target_branch, branch_type, project)
      if branch_type == 'default'
        target_branch == project.default_branch
      else # MRAP's `branch_type` only support `default` or `protected`
        ::ProtectedBranch.protected?(project, target_branch)
      end
    end

    def branch_matches_exception?(branch, exception)
      if exception[:name].present?
        branch == exception[:name]
      elsif exception[:pattern].present?
        RefMatcher.new(exception[:pattern]).matches?(branch)
      end
    end

    def license_override_purls_are_valid
      (typed_content['license_overrides'] || []).each do |override|
        purl = override['purl']
        next if purl.blank?

        begin
          Sbom::PackageUrl.parse(purl)
        rescue Sbom::PackageUrl::InvalidPackageUrl
          errors.add(:typed_content, format(_('contains invalid package URL: %{purl}'), purl: purl))
        end
      end
    end
  end
end
