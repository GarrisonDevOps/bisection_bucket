# frozen_string_literal: true

class ProtectedEnvironment < ApplicationRecord
  include ::Gitlab::Utils::StrongMemoize
  include FromUnion
  include Importable

  belongs_to :project
  belongs_to :group, inverse_of: :protected_environments
  has_many :deploy_access_levels, class_name: 'ProtectedEnvironments::DeployAccessLevel', inverse_of: :protected_environment
  has_many :approval_rules, class_name: 'ProtectedEnvironments::ApprovalRule', inverse_of: :protected_environment

  accepts_nested_attributes_for :deploy_access_levels, allow_destroy: true
  accepts_nested_attributes_for :approval_rules, allow_destroy: true

  validates :deploy_access_levels, length: { minimum: 1 }, unless: :importing?
  validates :name, presence: true
  validate :valid_tier_name, if: :group_level?
  validates :required_approval_count, numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 5 }

  scope :sorted_by_name, -> { order(:name) }

  scope :with_environment_id, -> do
    select('protected_environments.*, environments.id AS environment_id')
      .joins('LEFT OUTER JOIN environments ON ' \
             'protected_environments.name = environments.name  ' \
             'AND protected_environments.project_id = environments.project_id')
  end

  scope :for_groups, ->(group_ids) do
    where(group_id: group_ids).order(:name).preload(:deploy_access_levels)
  end

  class << self
    def names_for_projects(project_ids)
      where(project_id: project_ids).pluck(:name)
    end

    def tiers_for_groups(group_ids)
      where(group_id: group_ids).pluck(:name)
    end

    def revoke_user(user)
      revoke_approver(:user_id, user.id)
    end

    def revoke_group(group)
      revoke_approver(:group_id, group.id)
    end

    # Runs from Group's before_destroy callback. Reassigns the group's
    # sole-approver rules to a Maintainer-level fallback instead of
    # blocking deletion. Returns the reassigned rules to audit-log.
    def reassign_sole_group_approver(group)
      approval_rule_table = ProtectedEnvironments::ApprovalRule.arel_table

      transaction do
        protected_environment_ids = ProtectedEnvironments::ApprovalRule
          .where(group_id: group.id)
          .distinct
          .pluck(:protected_environment_id)

        next [] if protected_environment_ids.blank?

        # Skip group-level environments in the group's own hierarchy - the
        # group_id FK cascades to namespaces. Projects need no equivalent
        # check: all are already destroyed by the time this callback runs.
        own_hierarchy_environment_ids = where(id: protected_environment_ids)
          .where(group_id: group.self_and_descendant_ids)
          .pluck(:id)

        protected_environment_ids -= own_hierarchy_environment_ids

        next [] if protected_environment_ids.blank?

        # Locks every approval rule on these environments, not the parent
        # protected_environment row: a lock on the parent does not block a
        # concurrent DELETE of these child rows, so a concurrent revoke of
        # a different approver would otherwise race this check. Does not
        # stop a concurrent ProtectedEnvironments::UpdateService from
        # removing the other approver's rule right after this transaction
        # commits; that gap is untouched by this lock.
        locked_rule_ids = ProtectedEnvironments::ApprovalRule
          .where(protected_environment_id: protected_environment_ids)
          .lock
          .order(:id)
          .pluck(:id)

        environments_with_other_approver = ProtectedEnvironments::ApprovalRule
          .where(id: locked_rule_ids)
          .where(approval_rule_table[:group_id].is_distinct_from(group.id))
          .distinct
          .pluck(:protected_environment_id)

        reassignable_environment_ids = protected_environment_ids - environments_with_other_approver

        reassign_and_collapse_duplicates(:group_id, group.id, reassignable_environment_ids)
      end
    end

    # Runs from User's before_destroy callback, since approval_rules.user_id
    # is ON DELETE CASCADE and would otherwise delete the rule with the
    # user. Reassigns it to a Maintainer fallback; returns reassigned rules.
    def reassign_sole_user_approver(user)
      approval_rule_table = ProtectedEnvironments::ApprovalRule.arel_table

      transaction do
        protected_environment_ids = ProtectedEnvironments::ApprovalRule
          .where(user_id: user.id)
          .distinct
          .pluck(:protected_environment_id)

        next [] if protected_environment_ids.blank?

        # Locks every approval rule on these environments, not the parent
        # protected_environment row: a lock on the parent does not block a
        # concurrent DELETE of these child rows, so a concurrent revoke of
        # a different approver would otherwise race this check. Does not
        # stop a concurrent ProtectedEnvironments::UpdateService from
        # removing the other approver's rule right after this transaction
        # commits; that gap is untouched by this lock.
        locked_rule_ids = ProtectedEnvironments::ApprovalRule
          .where(protected_environment_id: protected_environment_ids)
          .lock
          .order(:id)
          .pluck(:id)

        environments_with_other_approver = ProtectedEnvironments::ApprovalRule
          .where(id: locked_rule_ids)
          .where(approval_rule_table[:user_id].is_distinct_from(user.id))
          .distinct
          .pluck(:protected_environment_id)

        reassignable_environment_ids = protected_environment_ids - environments_with_other_approver

        reassign_and_collapse_duplicates(:user_id, user.id, reassignable_environment_ids)
      end
    end

    def for_environment(environment)
      raise ArgumentError unless environment.is_a?(::Environment)

      key = "protected_environment:for_environment:#{environment.id}"

      ::Gitlab::SafeRequestStore.fetch(key) { for_environments([environment]) }
    end

    def for_environments(environments)
      raise ArgumentError, 'Environments must be in the same project' if environments.map(&:project_id).uniq.size > 1

      project_id = environments.first.project_id
      group_ids = environments.first.project.ancestors_upto_ids
      names = environments.map(&:name)
      tiers = environments.map(&:tier)

      from_union([
        where(project: project_id, name: names),
        where(group: group_ids, name: tiers)
      ])
    end

    private

    # Revokes this approver's deploy access on every protected environment
    # in scope. Also removes their approval rule, but only where another
    # approver remains, so revoking access never drops an environment's
    # required approvals to zero.
    def revoke_approver(column, approver_id)
      scope_values = current_scope&.where_values_hash || {}
      scoped_id = scope_values['project_id']

      # Asserts a single id, not just that the key is present:
      # where(project_id: [a, b]) and a subquery scope both leave the key
      # present but would lock and delete across multiple projects, or,
      # for where(project_id: nil), every group-level environment in the
      # instance.
      unless scoped_id.is_a?(Integer)
        raise ArgumentError,
          'revoke_user/revoke_group must be called on a relation scoped to a single project_id'
      end

      transaction do
        protected_environment_ids = pluck(:id)

        ProtectedEnvironments::DeployAccessLevel
          .where(protected_environment_id: protected_environment_ids, column => approver_id)
          .delete_all

        approval_rule_table = ProtectedEnvironments::ApprovalRule.arel_table

        # Locks every approval rule in scope, in id order, so a concurrent
        # revoke of a different approver on the same environment sees a
        # consistent picture instead of racing this transaction - locking
        # the parent protected_environment row instead doesn't block a
        # DELETE on these child rows at all. Does not stop a concurrent
        # ProtectedEnvironments::UpdateService from removing the other
        # approver's rule right after this transaction commits; that gap
        # is untouched by this lock.
        locked_rule_ids = ProtectedEnvironments::ApprovalRule
          .where(protected_environment_id: protected_environment_ids)
          .lock
          .order(:id)
          .pluck(:id)

        environments_with_other_approvers = ProtectedEnvironments::ApprovalRule
          .where(id: locked_rule_ids)
          .where(approval_rule_table[column].is_distinct_from(approver_id))
          .distinct
          .pluck(:protected_environment_id)

        ProtectedEnvironments::ApprovalRule
          .where(protected_environment_id: environments_with_other_approvers, column => approver_id)
          .delete_all
      end
    end

    # At most one rule naming a given approver on one environment can ever
    # be satisfied - Environment#find_approval_rule_for always attributes
    # an approval to the first match - so collapse all of them to one rule
    # per environment before reassigning, instead of leaving permanently
    # unsatisfiable duplicates behind.
    def reassign_and_collapse_duplicates(column, approver_id, protected_environment_ids)
      # Eager-loaded for callers that read protected_environment off each
      # returned rule (audit logging); nothing below uses it directly.
      ProtectedEnvironments::ApprovalRule
        .where(protected_environment_id: protected_environment_ids, column => approver_id)
        .includes(:protected_environment)
        .order(:id)
        .group_by(&:protected_environment_id)
        .map do |_protected_environment_id, rules|
          survivor, *duplicates = rules
          ProtectedEnvironments::ApprovalRule.where(id: duplicates).delete_all if duplicates.any?
          survivor.update!(column => nil, access_level: Gitlab::Access::MAINTAINER)
          survivor
        end
    end
  end

  def accessible_to?(user)
    deploy_access_levels
      .any? { |deploy_access_level| deploy_access_level.check_access(user) }
  end

  def container_access_level(user)
    if project_level?
      project.team.max_member_access(user&.id)
    elsif group_level?
      group.max_member_access_for_user(user)
    end
  end

  def project_level?
    project_id.present?
  end

  def group_level?
    group_id.present?
  end

  private

  def valid_tier_name
    unless Environment.tiers[name]
      errors.add(:name, "must be one of environment tiers: #{Environment.tiers.keys.join(', ')}.")
    end
  end
end
