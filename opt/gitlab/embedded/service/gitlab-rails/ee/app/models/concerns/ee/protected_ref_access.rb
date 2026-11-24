# frozen_string_literal: true

# EE-specific code related to protected branch/tag access levels.
#
# Note: Don't directly include this concern into a model class.
# Instead, include `ProtectedBranchAccess` or `ProtectedTagAccess`, which in
# turn include this concern. A number of methods here depend on
# `ProtectedRefAccess` being next up in the ancestor chain.

module EE
  module ProtectedRefAccess
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    DEVELOPER_OWNER_ACCESS = ::Gitlab::Access::DEVELOPER..::Gitlab::Access::OWNER.freeze

    module Scopes
      extend ActiveSupport::Concern

      included do
        belongs_to :user
        belongs_to :group

        protected_ref_fk = "#{module_parent.model_name.singular}_id"
        with_options uniqueness: { scope: protected_ref_fk, allow_nil: true } do
          validates :group_id
          validates :user_id
        end

        # Skip validations when importing
        # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/108342
        with_options unless: :importing? do
          validates :group_id, :user_id, absence: true, if: :user_and_group_not_assignable?

          validates :group, presence: true, if: %i[group_id user_or_group_assignable?]
          validates :user, presence: true, if: %i[user_id user_or_group_assignable?]

          validate :validate_group_membership, if: %i[group user_or_group_assignable?]
          validate :validate_user_membership, if: %i[user user_or_group_assignable?]
        end

        scope :by_user, ->(user) { where(user_id: user) }
        scope :by_group, ->(group) { where(group_id: group) }
        scope :for_user, -> { where.not(user_id: nil) }
        scope :for_group, -> { where.not(group_id: nil) }
      end
    end

    class_methods do
      def non_role_types
        super.concat(%i[user group])
      end
    end

    override :type
    def type
      return :user if user_id || user
      return :group if group_id || group

      super
    end

    private

    def humanize_user
      user&.name || 'User'
    end

    def humanize_group
      group&.name || 'Group'
    end

    # current_project is only available when evaluating a group-level protected
    # branch. We only allow role based access levels at the group-level so we
    # can ignore it here.
    def user_access_allowed?(current_user, _current_project)
      current_user.id == user_id && protected_ref_project.member?(current_user)
    end

    def group_access_allowed?(current_user, _current_project)
      # For protected branches, only groups that are invited to the
      # protected_ref_project can granted push and merge access. This feature
      # does not work for groups that are ancestors of the
      # protected_ref_project.  See
      # https://gitlab.com/gitlab-org/gitlab/-/issues/427486.  Hence, we only
      # consider the role of the user in the group limited by the max role of
      # the project_group_link.
      #
      # We do not use the access level provided by direct membership to the
      # protected_ref_project or inherited through ancestor groups of the
      # protected_ref_project.  See
      # https://gitlab.com/gitlab-org/gitlab/-/issues/423835

      return false unless group_has_developer_access_to_project?

      group.members.exists?(user: current_user, access_level: DEVELOPER_OWNER_ACCESS)
    end

    def user?
      type == :user
    end

    def group?
      type == :group
    end

    # We don't need to validate the license if this access applies to a role.
    #
    # If it applies to a user/group we can only skip validation
    # `nil`-validation if the feature is available
    def user_or_group_assignable?
      !role? && protected_ref_project&.feature_available?(:protected_refs_for_users)
    end

    def user_and_group_not_assignable?
      !user_or_group_assignable?
    end

    def validate_group_membership
      return if group_has_developer_access_to_project?

      errors.add(:group, 'does not have access to the project')
    end

    def validate_user_membership
      return if protected_ref_project.member?(user)

      errors.add(:user, 'is not a member of the project')
    end

    def group_has_developer_access_to_project?
      protected_ref_project.project_group_links.exists?(group: group, group_access: DEVELOPER_OWNER_ACCESS)
    end
  end
end
