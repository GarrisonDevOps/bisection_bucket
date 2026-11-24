# frozen_string_literal: true

require 'forwardable'

# A state object to centralize logic related to various approval related states.
# This reduce interface footprint on MR and allows easier cache invalidation.
class ApprovalState
  extend Forwardable
  include ::Gitlab::Utils::StrongMemoize

  # Guards the create flow while code owner approval rules are synced
  # asynchronously (NewMergeRequestWorker -> SyncCodeOwnerApprovalRulesWorker),
  # which can take up to a few minutes.
  TEMPORARILY_UNAPPROVED_TTL = 5.minutes

  # Guards the push/reset flow only until MergeRequestResetApprovalsWorker runs
  # (~10s later). Kept short so a merge request that is flagged but not reset
  # (e.g. it has no approvals) is not blocked for longer than necessary.
  TEMPORARILY_UNAPPROVED_TTL_ON_RESET = 15.seconds

  attr_reader :merge_request, :project

  def_delegators :@merge_request, :merge_status, :approved_by_users, :approvals, :approval_feature_available?, :approved_by?
  alias_method :approved_approvers, :approved_by_users

  def initialize(merge_request, target_branch: nil)
    @merge_request = merge_request
    @project = merge_request.target_project
    @target_branch = target_branch || merge_request.target_branch
  end

  def wrapped_approval_rules
    strong_memoize(:wrapped_approval_rules) do
      next [] unless approval_feature_available?

      if merge_request.merged?
        # After merging, we have historical data that we contain invalid approval rules associated with
        # the merge request. We should remove any of these invalid approver rules.
        # We also removed any that are not approved, as they would have not been
        # applicable at the time of merge.
        (all_approval_rules - invalid_approvers_rules).select(&:approved?)
      else
        all_approval_rules
      end
    end
  end

  def grouped_approval_rules
    strong_memoize(:grouped_approval_rules) do
      code_owners, other_rules = wrapped_approval_rules.partition(&:code_owner?)

      other_rules + group_code_owner_rules(code_owners)
    end
  end

  # Determines which set of rules to use (MR or project)
  def approval_rules_overwritten?
    project.can_override_approvers? && user_defined_merge_request_rules.any?
  end
  alias_method :approvers_overwritten?, :approval_rules_overwritten?

  def approval_needed?
    return false unless project.feature_available?(:merge_request_approvers)

    wrapped_approval_rules.any? { |rule| rule.approvals_required > 0 }
  end

  def approved?
    return false if temporarily_unapproved?

    all_approval_rules_approved?
  end
  strong_memoize_attr :approved?

  def all_approval_rules_approved?
    wrapped_approval_rules.all?(&:approved?)
  end

  def expire_unapproved_key!
    delete_legacy_temporarily_unapproved_key!

    if Feature.enabled?(:deterministic_approval_rules_sync, merge_request.project)
      approval_rules_sync_coordinator.clear_sync_state!
    end

    merge_request.delete_approval_mergeability_cache
  end

  def temporarily_unapprove!(ttl = TEMPORARILY_UNAPPROVED_TTL)
    Gitlab::Redis::SharedState.with do |redis|
      redis.set(temporarily_unapproved_cache_key, true, ex: ttl)
    end
    clear_memoization(:legacy_temporarily_unapproved)

    merge_request.delete_approval_mergeability_cache
  end

  def temporarily_unapproved?(memoize: false)
    unless Feature.enabled?(:deterministic_approval_rules_sync, merge_request.project)
      return legacy_temporarily_unapproved?(memoize: memoize)
    end

    legacy_temporarily_unapproved?(memoize: memoize) || approval_rules_sync_coordinator.any_sync_in_progress?
  end

  def approvals_required
    strong_memoize(:approvals_required) do
      total_required(code_owner_rules_required)
    end
  end

  def grouped_approvals_required
    strong_memoize(:grouped_approvals_required) do
      total_required(grouped_code_owner_rules.sum(&:approvals_required))
    end
  end

  def code_owner_rules_required
    strong_memoize(:code_owner_rules_required) do
      code_owner_rules.sum(&:approvals_required)
    end
  end

  def report_approver_rules_required
    strong_memoize(:report_approver_rules_required) do
      # Invalid fail-open rules need no approvals, so they must not count toward the total
      report_approver_rules.reject(&:invalid_fail_open?).sum(&:approvals_required)
    end
  end

  def regular_rules_required
    strong_memoize(:regular_rules_required) do
      regular_approval_rules.sum(&:approvals_required)
    end
  end

  def any_approver_rules_required
    strong_memoize(:any_approver_rules_required) do
      any_approver_approval_rules.sum(&:approvals_required)
    end
  end

  # Number of approvals remaining (excluding existing approvals) before the MR is
  # considered approved.
  def approvals_left
    strong_memoize(:approvals_left) do
      total_left(code_owner_rules_left)
    end
  end

  def grouped_approvals_left
    strong_memoize(:grouped_approvals_left) do
      total_left(grouped_code_owner_rules.sum(&:approvals_left))
    end
  end

  def code_owner_rules_left
    strong_memoize(:code_owner_rules_left) do
      code_owner_rules.sum(&:approvals_left)
    end
  end

  def report_approver_rules_left
    strong_memoize(:report_approver_rules_left) do
      report_approver_rules.sum(&:approvals_left)
    end
  end

  def regular_rules_left
    strong_memoize(:regular_rules_left) do
      regular_approval_rules.sum(&:approvals_left)
    end
  end

  def any_approver_rules_left
    strong_memoize(:any_approver_rules_left) do
      any_approver_approval_rules.sum(&:approvals_left)
    end
  end

  def approval_rules_left
    rules = if any_approver_rules_left <= regular_rules_left + code_owner_rules_left + report_approver_rules_left
              wrapped_approval_rules.reject(&:any_approver?)
            else
              wrapped_approval_rules
            end

    rules.reject(&:approved?)
  end

  def approvers
    strong_memoize(:approvers) { filtered_approvers(target: :approvers) }
  end

  def overall_approver_ids
    if approvals.loaded?
      approvals.map(&:user_id).to_set
    else
      approvals.distinct.pluck(:user_id).to_set # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- all approver IDs are required to evaluate approval rules
    end
  end
  strong_memoize_attr :overall_approver_ids

  # @param code_owner [Boolean]
  # @param target [:approvers, :users]
  # @param unactioned [Boolean]
  def filtered_approvers(code_owner: true, target: :approvers, unactioned: false)
    rules = user_defined_rules + report_approver_rules
    rules.concat(code_owner_rules) if code_owner

    filter_approvers(rules.flat_map(&target), unactioned: unactioned)
  end

  def unactioned_approvers
    strong_memoize(:unactioned_approvers) { approvers - approved_approvers }
  end

  # TODO order by relevance
  def suggested_approvers(current_user:)
    # Ignore approvers from rules containing hidden groups
    rules = wrapped_approval_rules.reject do |rule|
      ApprovalRules::GroupFinder.new(rule, current_user).contains_hidden_groups?
    end

    filter_approvers(rules.flat_map(&:approvers), unactioned: true)
  end

  # Members that can satisfy the synthetic "any approver" rule, which stores no
  # approvers because it means "anyone who can approve". Narrowed to the direct
  # members that can also merge the target branch, since approving only takes
  # Developer access.
  #
  # Only for recommending reviewers, where a bounded and ranked list is what the
  # caller wants. The approval widget reads the rule's own approvers instead.
  # https://gitlab.com/gitlab-org/gitlab/-/issues/604144
  def any_approver_candidates(limit:)
    access_level = role_access_level_to_merge_target_branch
    candidates = direct_members_with_access_level(access_level, limit: limit) if access_level

    candidates.presence || direct_members_with_access_level(::Gitlab::Access::DEVELOPER, limit: limit)
  end

  def eligible_for_approval_by?(user)
    return false unless user
    return false unless Ability.allowed?(user, :approve_merge_request, merge_request)

    return true if unactioned_approvers.include?(user)
    # Users can only approve once.
    return false if approved_by?(user)
    # At this point, follow self-approval rules. Otherwise authors must
    # have been in the list of unactioned_approvers to have been approved.
    return false if !authors_can_approve? && merge_request.author == user

    unless committers_can_approve?
      committer_users = merge_request.committers_to_filter_from_approvers

      return false if committer_users.include?(user)
    end

    true
  end

  def authors_can_approve?
    merge_request.merge_requests_author_approval?
  end

  def committers_can_approve?
    !merge_request.merge_requests_disable_committers_approval?
  end

  # TODO: remove after #1979 is closed
  # This is a temporary method for backward compatibility
  # before introduction of approval rules.
  # This avoids re-queries.
  # https://gitlab.com/gitlab-org/gitlab/issues/33329
  def first_regular_rule
    strong_memoize(:first_regular_rule) do
      user_defined_rules.first
    end
  end

  def user_defined_rules
    strong_memoize(:user_defined_rules) do
      if approval_rules_overwritten? || (merge_request.merged? && user_defined_merge_request_rules.any?)
        user_defined_merge_request_rules
      else
        project.visible_user_defined_rules(branch: target_branch).map do |rule|
          ApprovalWrappedRule.wrap(merge_request, rule)
        end
      end
    end
  end

  # This is the required + optional approval count
  def total_approvals_count
    approvals.size
  end

  def invalid_approvers_rules
    strong_memoize(:invalid_approvers_rules) do
      all_approval_rules.select do |rule|
        next if rule.any_approver?
        next if rule.approvers.any? && rule.approvers.size >= rule.approvals_required

        if rule.code_owner?
          rule.branch_requires_code_owner_approval?
        else
          rule.approvals_required > rule.approvers.size
        end
      end
    end
  end

  private

  attr_reader :target_branch

  def total_required(code_owner_required)
    [regular_rules_required + code_owner_required + report_approver_rules_required, any_approver_rules_required].max
  end

  def total_left(code_owner_left)
    [regular_rules_left + code_owner_left + report_approver_rules_left, any_approver_rules_left].max
  end

  def temporarily_unapproved_cache_key
    "mr_#{merge_request.id}_cannot_merge"
  end

  # Once a caller memoizes, later calls on this object reuse that read until the key is set or deleted
  def legacy_temporarily_unapproved?(memoize: false)
    return legacy_temporarily_unapproved_key_exists? unless memoize || strong_memoized?(:legacy_temporarily_unapproved)

    strong_memoize(:legacy_temporarily_unapproved) { legacy_temporarily_unapproved_key_exists? }
  end

  def legacy_temporarily_unapproved_key_exists?
    Gitlab::Redis::SharedState.with { |redis| redis.exists?(temporarily_unapproved_cache_key) }
  end

  def delete_legacy_temporarily_unapproved_key!
    clear_memoization(:legacy_temporarily_unapproved)
    Gitlab::Redis::SharedState.with { |redis| redis.del(temporarily_unapproved_cache_key) }
  end

  def approval_rules_sync_coordinator
    ::MergeRequests::ApprovalRulesSyncCoordinator.new(merge_request)
  end

  # Direct members only. Membership of an ancestor group grants access to every
  # project underneath it, so inheritance puts people who never work on the project
  # - an owner of the top level group, say - in the pool.
  # https://gitlab.com/gitlab-org/gitlab/-/issues/604144#note_3652624880
  #
  # The access level is the authorized one, which is the highest of the direct and
  # the inherited membership, because that is the access a candidate would approve
  # and merge with.
  def direct_members_with_access_level(access_level, limit:)
    candidates = project.users
      .with_state(:active)
      .human
      .joins(:project_authorizations)
      .where(project_authorizations: { project_id: project.id, access_level: access_level.. })
      .where.not(id: merge_request.author_id)

    # Recommending someone who cannot approve leaves the rule unsatisfiable. The
    # author is out either way, since nobody reviews their own merge request;
    # committers and banned members only when they cannot approve.
    unless committers_can_approve?
      candidates = candidates.where.not(id: merge_request.committer_ids_to_filter_from_approvers)
    end

    reject_namespace_banned(candidates).order_recent_last_activity.limit(limit)
  end

  # A namespace ban leaves the membership, the authorization and the user active,
  # so a banned member passes every filter above, but ProjectPolicy prevents
  # everything on the project. Mirrors the role of #user_banned_from_namespace.
  #
  # Gated on the download limit, because that is what the policy checks: a ban
  # row with the limit off does not stop anyone from approving.
  def reject_namespace_banned(candidates)
    root_ancestor = project.root_ancestor
    return candidates unless root_ancestor.is_a?(::Group)
    return candidates unless root_ancestor.unique_project_download_limit_enabled?

    candidates.where.not(id: ::Namespaces::NamespaceBan.where(namespace: root_ancestor).select(:user_id))
  end

  # Lowest role that can merge the target branch, nil when none can. Mirrors the
  # role based part of Gitlab::UserAccess#can_update_branch?, where push access
  # to a protected branch also allows merging. #any_approver_candidates falls back
  # when this is nil or when no direct member holds it, since user, group and
  # member role access levels are not a floor.
  def role_access_level_to_merge_target_branch
    access_levels = %i[merge push].flat_map do |action|
      ::ProtectedBranch.access_levels_for_ref(
        target_branch, action: action, protected_refs: project.all_protected_branches
      )
    end

    access_levels
      .select(&:role?)
      .map(&:access_level)
      .select { |level| level.between?(::Gitlab::Access::DEVELOPER, ::Gitlab::Access::OWNER) }
      .min
  end

  def filter_approvers(approvers, unactioned:)
    approvers = approvers.uniq
    approvers -= approved_approvers if unactioned
    approvers
  end

  def user_defined_merge_request_rules
    strong_memoize(:user_defined_merge_request_rules) do
      regular_rules =
        wrapped_rules.select(&:regular?).sort_by(&:id)

      any_approver_rules =
        wrapped_rules.select(&:any_approver?)

      rules = any_approver_rules + regular_rules
      project.multiple_approval_rules_available? ? rules : rules.take(1)
    end
  end

  def code_owner_rules
    strong_memoize(:code_owner_rules) do
      wrapped_rules.select(&:code_owner?)
    end
  end

  def report_approver_rules
    strong_memoize(:report_approver_rules) do
      wrapped_rules.select(&:report_approver?)
    end
  end

  def regular_approval_rules
    strong_memoize(:regular_approval_rules) do
      wrapped_approval_rules.select(&:regular?)
    end
  end

  def any_approver_approval_rules
    strong_memoize(:any_approver_approval_rules) do
      wrapped_approval_rules.select(&:any_approver?)
    end
  end

  def wrapped_rules
    strong_memoize(:wrapped_rules) do
      rules = if merge_request.merged?
                merge_request.applicable_post_merge_approval_rules
              elsif Feature.enabled?(:v2_approval_rules, project)
                merge_request.v2_approval_rules
              else
                merge_request.approval_rules.applicable_to_branch(target_branch)
              end

      preload_approver_associations(rules)

      grouped_merge_request_rules = rules.group_by do |rule|
        rule.from_scan_result_policy? ? :scan_finding : rule.report_type
      end

      grouped_merge_request_rules.flat_map do |report_type, merge_request_rules|
        Approvals::WrappedRuleSet.wrap(merge_request, merge_request_rules, report_type).wrapped_rules
      end
    end
  end

  def grouped_code_owner_rules
    strong_memoize(:grouped_code_owner_rules) do
      group_code_owner_rules(code_owner_rules.select { |rule| rule.approvals_required > 0 })
    end
  end

  def group_code_owner_rules(rules)
    sectioned, unsectioned = rules.partition(&:section)

    unsectioned + sectioned.group_by { |rule| [rule.section, rule.approvers.map(&:id).sort] }
      .map { |_key, section_rules| ::MergeRequests::ApprovalGroupedCodeOwnerRule.new(merge_request, section_rules) }
  end

  def preload_approver_associations(rules)
    return if rules.empty?

    associations = if rules.first.is_a?(MergeRequests::ApprovalRule)
                     [:approver_users, :group_users]
                   else
                     [:users, :group_users]
                   end

    ActiveRecord::Associations::Preloader.new(
      records: rules,
      associations: associations
    ).call
  end

  def all_approval_rules
    strong_memoize(:all_approval_rules) do
      next [] unless approval_feature_available?

      user_defined_rules + code_owner_rules + report_approver_rules
    end
  end
end
