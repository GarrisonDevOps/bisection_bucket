# frozen_string_literal: true

# A common state computation interface to wrap around ApprovalRuleLike models.
#
# There are 2 types of approval rules (`ApprovalProjectRule` and
# `ApprovalMergeRequestRule`), we want to get the data we need for the approval
# state of each rule via a common interface. That depends on the approvals data
# of a merge request.
#
# `ApprovalProjectRule` doesn't have access to the merge request unlike
# `ApprovalMergeRequestRule`. Given that, instead of having different checks and
# methods when dealing with a `ApprovalProjectRule`, having a common interface
# is easier and simpler to interact with.
#
# Different types of `ApprovalWrappedRule` also helps since we have different
# `rule_type`s that can behave differently.
class ApprovalWrappedRule
  extend Forwardable
  include Gitlab::Utils::StrongMemoize

  attr_reader :merge_request, :approval_rule

  def_delegators(
    :@approval_rule,
    :regular?, :any_approver?, :code_owner?, :report_approver?,
    :overridden?, :id, :users, :groups, :code_owner, :from_scan_result_policy?, :warn_mode_policy?,
    :source_rule, :rule_type, :report_type, :section, :to_global_id, :rule_project
  )

  def self.wrap(merge_request, rule)
    if rule.any_approver?
      ApprovalWrappedAnyApproverRule.new(merge_request, rule)
    elsif rule.code_owner?
      ApprovalWrappedCodeOwnerRule.new(merge_request, rule)
    else
      ApprovalWrappedRule.new(merge_request, rule)
    end
  end

  def initialize(merge_request, approval_rule)
    @merge_request = merge_request
    @approval_rule = approval_rule
  end

  def project
    @merge_request.target_project
  end

  def approvers
    strong_memoize(:approvers) do
      filter_approvers(@approval_rule.approvers)
    end
  end

  def declarative_policy_delegate
    @approval_rule
  end

  # @return [Array<User>] of users who have approved the merge request
  #
  # This is dynamically calculated unless it is persisted as `approved_approvers`.
  #
  # After merge, the approval state should no longer change.
  # We persist this so if project level rule is changed in the future,
  # return result won't be affected.
  #
  # For open MRs, it is dynamically calculated because:
  # - Additional complexity to add update hooks
  # - DB updating many MRs for one project rule change is inefficient
  def approved_approvers
    if merge_request.merged? && approval_rule.is_a?(ApprovalMergeRequestRule) && approval_rule.approved_approvers.any?
      return approval_rule.approved_approvers
    end

    strong_memoize(:approved_approvers) do
      approvers.select do |approver|
        overall_approver_ids.include?(approver.id)
      end
    end
  end

  def commented_approvers
    strong_memoize(:commented_approvers) do
      merge_request.user_note_authors & approvers
    end
  end

  def approved?
    strong_memoize(:approved) do
      approvals_left <= 0 || (invalid_rule? && allow_merge_when_invalid?) ||
        approval_rule_dismissed? || approval_rule_bypassed?
    end
  end

  def invalid_rule?
    !any_approver? && approvals_required > approvers.size
  end

  def invalid_fail_open?
    invalid_rule? && fail_open?
  end

  def allow_merge_when_invalid?
    return true if fail_open?

    !from_scan_result_policy? ||
      Security::OrchestrationPolicyConfiguration.policy_management_project?(project)
  end

  def scan_result_policies
    policy_configuration_id = approval_rule.security_orchestration_policy_configuration_id

    return unless policy_configuration_id

    merge_request
      .approval_rules.for_policy_configuration(policy_configuration_id)
      .for_policy_index(approval_rule.orchestration_policy_idx)
      .select(:report_type, :name, :approvals_required, :approval_policy_action_idx)
  end

  def policy_has_multiple_actions?
    policy_configuration = approval_rule.security_orchestration_policy_configuration
    return false unless policy_configuration

    scan_result_policies.any? { |rule| rule.approval_policy_action_idx > 0 }
  end

  # Number of approvals remaining (excluding existing approvals)
  # before the rule is considered approved.
  #
  # If there are fewer potential approvers than approvals left,
  # users should either reduce `approvals_required`
  # and/or allow MR authors to approve their own merge
  # requests (in case only one approval is needed).
  def approvals_left
    strong_memoize(:approvals_left) do
      next 0 if invalid_fail_open?

      approvals_left_count = approvals_required - approved_approvers.size

      [approvals_left_count, 0].max
    end
  end

  def unactioned_approvers
    approvers - approved_approvers
  end

  def name
    return approval_rule.name unless from_scan_result_policy?

    if policy_has_multiple_actions?
      "#{approval_rule.policy_name} - Action #{approval_rule.approval_policy_action_idx + 1}"
    else
      approval_rule.policy_name
    end
  end

  def approvals_required
    return 0 if approval_rule_dismissed? || approval_rule_bypassed?

    @approval_rule.approvals_required
  end

  def fail_open?
    return false unless from_scan_result_policy?

    approval_rule.approval_policy_source&.fail_open? || false
  end

  def originates_from_project?
    return unless Feature.enabled?(:v2_approval_rules, @approval_rule&.project)
    return unless @approval_rule.respond_to?(:originates_from_project?)

    @approval_rule.originates_from_project?
  end

  def originates_from_merge_request?
    return unless Feature.enabled?(:v2_approval_rules, @approval_rule&.project)
    return unless @approval_rule.respond_to?(:originates_from_merge_request?)

    @approval_rule.originates_from_merge_request?
  end

  def user_defined?
    return unless Feature.enabled?(:v2_approval_rules, @approval_rule&.project)

    @approval_rule.user_defined?
  end

  # Explains why the rule blocks the merge request. Only supported for the
  # Coverage-Check rule, and only while the `coverage_minimum_threshold`
  # feature flag is enabled.
  #
  # @return [Gitlab::Ci::CoverageApprovalCheck::Result, nil] nil when the rule does not block
  def blockage_reason
    return unless report_approver? && report_type == 'code_coverage'
    return unless Feature.enabled?(:coverage_minimum_threshold, project)
    return if approved?

    result = ::Gitlab::Ci::CoverageApprovalCheck.check(
      merge_request: merge_request,
      pipeline: merge_request.head_pipeline,
      threshold: approval_rule.coverage_minimum_threshold
    )

    result if result.required?
  end
  strong_memoize_attr :blockage_reason

  private

  def approval_rule_dismissed?
    return false unless warn_mode_policy?

    violation = policy_violation
    return false unless violation

    violation.dismissed?
  end

  # There can only be one scan_result_policy_violation for each rule and merge request.
  def policy_violation
    approval_policy_rule_id = approval_rule.approval_policy_rule_id
    return unless approval_policy_rule_id

    merge_request.scan_result_policy_violations.find_by(approval_policy_rule_id: approval_policy_rule_id)
  end
  strong_memoize_attr :policy_violation

  def approval_rule_bypassed?
    return false unless from_scan_result_policy?

    security_policy = approval_rule&.approval_policy_rule&.security_policy
    return false unless security_policy

    security_policy.merge_request_bypassed?(merge_request)
  end

  def filter_approvers(approvers)
    prevents_author_approval = prevents_author_approval?
    prevents_committer_approval = prevents_committer_approval?

    return approvers unless prevents_author_approval || prevents_committer_approval

    approvers = filter_author_for_rule(approvers) if prevents_author_approval
    approvers = filter_committers_for_rule(approvers) if prevents_committer_approval
    approvers
  end

  # Policy rules apply only their own policy's approval settings. Other rules (for example
  # code owner rules) must apply the settings of every enforced policy the merge request violates.
  def prevents_author_approval?
    return approval_rule.prevents_author_approval? if approval_rule.approval_policy_source

    !merge_request.merge_requests_author_approval?
  end

  def prevents_committer_approval?
    return approval_rule.prevents_committer_approval? if approval_rule.approval_policy_source

    merge_request.merge_requests_disable_committers_approval?
  end

  # Excludes the author if 'author-approval' is explicitly disabled on instance,
  # group or project settings. For Ultimate projects, a scan result policy may
  # override this behaviour by its `approval_settings.prevent_approval_by_author` attribute.
  def filter_author_for_rule(users)
    return users unless merge_request.author

    if users.is_a?(ActiveRecord::Relation) && !users.loaded?
      users.where.not(id: merge_request.author_id)
    else
      users - [merge_request.author]
    end
  end

  # Excludes the author if 'committers-approval' is explicitly disabled on instance, group or
  # project settings.
  def filter_committers_for_rule(users)
    if users.is_a?(ActiveRecord::Relation) && !users.loaded?
      users.where.not(id: merge_request.committer_ids_to_filter_from_approvers)
    else
      users - merge_request.committers_to_filter_from_approvers
    end
  end

  def overall_approver_ids
    merge_request.approval_state.overall_approver_ids
  end
end
