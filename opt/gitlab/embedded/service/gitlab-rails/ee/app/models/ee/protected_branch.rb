# frozen_string_literal: true

module EE
  module ProtectedBranch
    extend ActiveSupport::Concern

    prepended do
      has_and_belongs_to_many :approval_project_rules
      # NOTE: This is used to prevent N+1 queries in BranchRulesResolver
      has_and_belongs_to_many :approval_project_rules_with_unique_policies,
        ->(protected_branch) { with_unique_policies_for_protected_branch(protected_branch) },
        class_name: 'ApprovalProjectRule'
      has_and_belongs_to_many :external_status_checks, class_name: '::MergeRequests::ExternalStatusCheck'

      has_many :required_code_owners_sections, class_name: "ProtectedBranch::RequiredCodeOwnersSection"

      protected_ref_access_levels :unprotect

      scope :preload_access_levels, -> do
        preload(
          merge_access_levels: [:user, :group, :member_role],
          push_access_levels: [:user, :group, :deploy_key, :member_role],
          unprotect_access_levels: [:user, :group, :member_role]
        )
      end

      attr_accessor :protected_from_deletion

      has_one :squash_option, class_name: 'Projects::BranchRules::SquashOption'
      has_one :merge_request_approval_setting, class_name: 'Projects::BranchRules::MergeRequestApprovalSetting'

      validate :validate_squash_option_not_wildcard,
        if: -> { squash_option.present? && (name_changed? || squash_option.new_record?) }
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      def branch_requires_code_owner_approval?(project, branch_name)
        return false unless project.code_owner_approval_required_available?

        ::Gitlab::SafeRequestStore.fetch(:"project-#{project.id}-branch-#{branch_name}") do
          project.all_protected_branches.requiring_code_owner_approval.matching(branch_name).any?
        end
      end

      override :can_update_security_orchestration_policy_project?
      def can_update_security_orchestration_policy_project?(user, project)
        ::Security::OrchestrationPolicyConfiguration.for_management_project(project.id).any? do |config|
          target = config.project || config.namespace
          Ability.allowed?(user, :update_security_orchestration_policy_project, target)
        end
      end
    end

    def code_owner_approval_required
      super && entity.code_owner_approval_required_available?
    end
    alias_method :code_owner_approval_required?, :code_owner_approval_required

    def modification_blocked_by_policy?(current_user = nil)
      return false unless ::Security::PolicyAvailability.any_available?(entity)

      case entity
      when Project
        modification_blocked_by_policy_result(current_user)
      when Group
        group_modification_blocked_by_policy_result(current_user)
      end
    end
    alias_method :modification_blocked_by_policy, :modification_blocked_by_policy?

    def warn_modification_blocked_by_policy?(current_user = nil)
      return false unless ::Security::PolicyAvailability.any_available?(entity)

      case entity
      when Project
        # Returns true if modification would be blocked by a warn-mode policy
        # (i.e., blocked when ignoring warn mode but not blocked normally)
        !modification_blocked_by_policy_result(current_user) &&
          modification_blocked_by_policy_ignore_warn_result(current_user)
      when Group
        !group_modification_blocked_by_policy_result(current_user) &&
          group_modification_blocked_by_policy_ignore_warn_result(current_user)
      end
    end
    alias_method :warn_modification_blocked_by_policy, :warn_modification_blocked_by_policy?

    def allow_force_push
      return false if protected_from_push_by_security_policy?

      super
    end

    def protected_from_push_by_security_policy?
      return false unless ::Security::PolicyAvailability.any_available?(entity)
      return false unless project_level?

      protected_from_push_by_policy_result
    end
    alias_method :protected_from_push_by_security_policy, :protected_from_push_by_security_policy?

    def warn_protected_from_push_by_security_policy?
      return false unless ::Security::PolicyAvailability.any_available?(entity)
      return false unless project_level?

      # Returns true if push would be blocked by a warn-mode policy
      # (i.e., blocked when ignoring warn mode but not blocked normally)
      !protected_from_push_by_policy_result && protected_from_push_by_policy_ignore_warn_result
    end
    alias_method :warn_protected_from_push_by_security_policy, :warn_protected_from_push_by_security_policy?

    def can_unprotect?(user)
      return true if unprotect_access_levels.empty?

      unprotect_access_levels.any? do |access_level|
        access_level.check_access(user)
      end
    end

    def supports_unprotection_restrictions?
      return false if group

      project.licensed_feature_available?(:unprotection_restrictions)
    end

    def inherited?
      !namespace_id.nil?
    end
    alias_method :inherited, :inherited?

    private

    def validate_squash_option_not_wildcard
      return unless wildcard?

      errors.add(:base, _('Squash option cannot be used with wildcard branch rules. Use an exact branch name.'))
    end

    def modification_blocked_by_policy_result(current_user = nil)
      ::Security::SecurityOrchestrationPolicies::ProtectedBranchesDeletionCheckService
        .new(project: entity, current_user: current_user)
        .execute([self])
        .any?
    end

    def modification_blocked_by_policy_ignore_warn_result(current_user = nil)
      ::Security::SecurityOrchestrationPolicies::ProtectedBranchesDeletionCheckService
        .new(project: entity, current_user: current_user, ignore_warn_mode: true)
        .execute([self])
        .any?
    end

    def group_modification_blocked_by_policy_result(current_user = nil)
      ::Security::SecurityOrchestrationPolicies::GroupProtectedBranchesDeletionCheckService
        .new(group: entity, current_user: current_user)
        .execute
    end

    def group_modification_blocked_by_policy_ignore_warn_result(current_user = nil)
      ::Security::SecurityOrchestrationPolicies::GroupProtectedBranchesDeletionCheckService
        .new(group: entity, current_user: current_user, ignore_warn_mode: true)
        .execute
    end

    def protected_from_push_by_policy_result
      @protected_from_push_by_policy_result ||=
        ::Security::SecurityOrchestrationPolicies::ProtectedBranchesPushService
          .new(project: project)
          .execute
          .include?(name)
    end

    def protected_from_push_by_policy_ignore_warn_result
      @protected_from_push_by_policy_ignore_warn_result ||=
        ::Security::SecurityOrchestrationPolicies::ProtectedBranchesPushService
          .new(project: project, ignore_warn_mode: true)
          .execute
          .include?(name)
    end
  end
end
