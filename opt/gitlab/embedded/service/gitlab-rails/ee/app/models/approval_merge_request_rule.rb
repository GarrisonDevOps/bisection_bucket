# frozen_string_literal: true

class ApprovalMergeRequestRule < ApplicationRecord
  include Gitlab::Utils::StrongMemoize
  include ApprovalRuleLike
  include UsageStatistics

  scope :not_matching_id, ->(ids) { code_owner.where.not(id: ids) }
  scope :matching_pattern, ->(pattern) { code_owner.where(name: pattern) }
  scope :preload_users_and_groups, -> { preload(:users, :groups) }

  scope :from_project_rule, ->(project_rule) do
    joins(:approval_merge_request_rule_source)
      .where(
        approval_merge_request_rule_sources: { approval_project_rule_id: project_rule.id }
      )
  end
  scope :for_unmerged_merge_requests, ->(merge_requests = nil) do
    query = joins(:merge_request).where.not(merge_requests: { state_id: MergeRequest.available_states[:merged] })

    if merge_requests
      query.where(merge_request_id: merge_requests)
    else
      query
    end
  end
  scope :for_merge_request_project, ->(project_id) { joins(:merge_request).where(merge_requests: { target_project_id: project_id }) }
  scope :for_project, ->(project_id) { where(project_id: project_id) }
  scope :code_owner_approval_optional, -> { code_owner.where(approvals_required: 0) }
  scope :code_owner_approval_required, -> { code_owner.where('approvals_required > 0') }
  scope :with_added_approval_rules, -> { left_outer_joins(:approval_merge_request_rule_source).where(approval_merge_request_rule_sources: { approval_merge_request_rule_id: nil }) }
  scope :applicable_post_merge, -> { where(applicable_post_merge: [true, nil]) }

  validates :name, uniqueness: { scope: [:merge_request_id, :rule_type, :section, :applicable_post_merge] }, unless: :from_scan_result_policy?
  validates :name, uniqueness: {
    scope: [
      :merge_request_id, :rule_type, :security_orchestration_policy_configuration_id,
      :orchestration_policy_idx, :approval_policy_action_idx
    ]
  }, if: :from_scan_result_policy?
  validates :rule_type, uniqueness: { scope: [:merge_request_id, :applicable_post_merge], message: proc { _('any-approver for the merge request already exists') } }, if: :any_approver?
  validates :role_approvers, inclusion: { in: Gitlab::Access.all_values }
  validate :role_approvers_only_for_code_owner_type

  belongs_to :merge_request, inverse_of: :approval_rules
  belongs_to :project

  # approved_approvers is only populated after MR is merged
  has_and_belongs_to_many :approved_approvers, class_name: 'User', join_table: :approval_merge_request_rules_approved_approvers
  has_many :approval_merge_request_rules_users
  has_many :scan_result_policy_violations, through: :scan_result_policy_read, source: :violations
  has_one :approval_merge_request_rule_source
  has_one :approval_project_rule, through: :approval_merge_request_rule_source
  has_one :approval_project_rule_project, through: :approval_project_rule, source: :project
  alias_method :source_rule, :approval_project_rule

  before_update :compare_with_project_rule

  validate :validate_approval_project_rule
  validate :merge_request_not_merged, unless: proc { merge_request.blank? || merge_request.finalizing_rules.present? }

  enum :rule_type, {
    regular: 1,
    code_owner: 2,
    report_approver: 3,
    any_approver: 4
  }

  alias_method :regular, :regular?
  alias_method :code_owner, :code_owner?

  scope :license_compliance, -> { report_approver.license_scanning }
  scope :coverage, -> { report_approver.code_coverage }
  scope :with_head_pipeline, -> { includes(merge_request: [:head_pipeline]) }
  scope :open_merge_requests, -> { merge(MergeRequest.opened) }
  scope :for_checks_that_can_be_refreshed, -> { license_compliance.open_merge_requests.with_head_pipeline }
  scope :with_projects_that_can_override_rules, -> do
    joins(:approval_project_rule_project)
      .where(projects: { disable_overriding_approvers_per_merge_request: [false, nil] })
  end
  scope :modified_from_project_rule, -> { with_projects_that_can_override_rules.where(modified_from_project_rule: true) }

  def self.find_or_create_code_owner_rule(merge_request, entry)
    merge_request.approval_rules.code_owner.where(name: entry.pattern).where(section: entry.section).first_or_create do |rule|
      rule.rule_type = :code_owner
      rule.approvals_required = entry.approvals_required
    end
  rescue ActiveRecord::RecordNotUnique
    retry
  end

  # Locks the rules until the enclosing transaction commits and returns their ids by scan result policy read.
  def self.lock_ids_by_scan_result_policy_read
    lock('FOR NO KEY UPDATE')
      .pluck(:scan_result_policy_id, :id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- at most one rule per merge request in the batch and stale read
      .group_by(&:first)
      .transform_values { |pairs| pairs.map(&:last) }
  end

  def merge_request_not_merged
    return unless merge_request.merged?

    errors.add(:merge_request, 'must not be merged')
  end

  def audit_add(_model)
    # no-op
    # only audit on project rule
  end

  def audit_remove(_model)
    # no-op
    # only audit on project rule
  end

  def project
    merge_request.target_project
  end
  alias_method :rule_project, :project

  def approval_project_rule_id=(approval_project_rule_id)
    self.approval_merge_request_rule_source ||= build_approval_merge_request_rule_source
    self.approval_merge_request_rule_source.approval_project_rule_id = approval_project_rule_id
  end

  # Users who are eligible to approve, including specified group members.
  # Excludes the author if 'self-approval' isn't explicitly
  # enabled on project settings.
  #
  # TODO: Consider removing this filtering logic and consolidating it in ApprovalWrappedRule
  # See: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/217325#note_2982431789
  #
  # @return [Array<User>]
  def approvers
    strong_memoize(:approvers) do
      scope_or_array = super

      next scope_or_array unless merge_request.author
      next scope_or_array if author_can_approve?

      if scope_or_array.respond_to?(:where)
        scope_or_array.where.not(id: merge_request.author)
      else
        scope_or_array - [merge_request.author]
      end
    end
  end

  def applicable_to_branch?(branch)
    return false unless policy_applies_to_target_branch?(branch)
    return false if branches_exempted_by_policy?
    return true unless self.approval_project_rule.present?
    return true if self.modified_from_project_rule

    self.approval_project_rule.applies_to_branch?(branch)
  end

  def branches_exempted_by_policy?
    approval_policy_rule.present? &&
      approval_policy_rule.branches_exempted_by_policy?(merge_request.source_branch, merge_request.target_branch)
  end

  def sync_approved_approvers
    # Before being merged, approved_approvers are dynamically calculated in
    #   ApprovalWrappedRule instead of being persisted.
    #
    return unless merge_request.merged? && merge_request.finalizing_rules.present?

    approvers = ApprovalWrappedRule.wrap(merge_request, self).approved_approvers

    self.approved_approver_ids = approvers.map(&:id)
  end

  def self.remove_required_approved(approval_rules)
    where(id: approval_rules).update_all(approvals_required: 0)
  end

  def vulnerability_states_for_branch
    states = self.vulnerability_states.presence || DEFAULT_VULNERABILITY_STATUSES
    return states if merge_request.target_default_branch?

    states & NEWLY_DETECTED_STATUSES
  end

  def hook_attrs
    {
      id: id,
      approvals_required: approvals_required,
      name: name,
      rule_type: rule_type,
      report_type: report_type,
      merge_request_id: merge_request_id,
      section: section,
      modified_from_project_rule: modified_from_project_rule,
      orchestration_policy_idx: orchestration_policy_idx,
      vulnerabilities_allowed: vulnerabilities_allowed,
      scanners: scanners,
      severity_levels: severity_levels,
      vulnerability_states: vulnerability_states,
      security_orchestration_policy_configuration_id: security_orchestration_policy_configuration_id,
      scan_result_policy_id: scan_result_policy_id,
      applicable_post_merge: applicable_post_merge,
      project_id: project_id,
      approval_policy_rule_id: approval_policy_rule_id,
      updated_at: updated_at,
      created_at: created_at
    }
  end

  def author_can_approve?
    !prevents_author_approval?
  end

  private

  def code_owner_role_approvers
    return User.none unless code_owner?

    role_approver_user_ids = project.project_members.with_roles(role_approvers).pluck_user_ids
    User.by_ids(role_approver_user_ids)
  end

  def role_approvers_only_for_code_owner_type
    return unless role_approvers.present? && !code_owner?

    errors.add(:role_approvers, "can only be added to codeowner type rules")
  end

  def compare_with_project_rule
    self.modified_from_project_rule = overridden? || false
  end

  def validate_approval_project_rule
    return if approval_project_rule.blank?
    return if merge_request.project == approval_project_rule.project

    errors.add(:approval_project_rule, 'must be for the same project')
  end

  def policy_applies_to_target_branch?(branch)
    return true unless approval_policy_rule

    approval_policy_rule.policy_applies_to_target_branch?(branch, project)
  end
end
