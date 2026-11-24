# frozen_string_literal: true

module EE
  module ProtectedBranchAccess # rubocop:disable Gitlab/BoundedContexts -- extending a previously established module
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    module Scopes
      extend ActiveSupport::Concern

      included do
        belongs_to :member_role, optional: true

        protected_ref_fk = "#{module_parent.model_name.singular}_id"
        validates :member_role_id, uniqueness: { scope: protected_ref_fk, allow_nil: true }
        validates :member_role, presence: true, if: -> { member_role_id.present? }

        validate :validate_member_role_namespace, if: -> { member_role_id.present? }, unless: :importing?
      end

      class_methods do
        def non_role_types
          super.concat(%i[member_role])
        end
      end
    end

    def type
      return :member_role if member_role_id || member_role

      super
    end

    def custom_roles_licensed?(current_project = nil)
      group = current_project&.root_ancestor ||
        protected_ref_project&.root_ancestor ||
        protected_branch_group&.root_ancestor
      group&.licensed_feature_available?(:custom_roles)
    end

    private

    def humanize_member_role
      member_role&.name || 'Custom Role'
    end

    def member_role?
      type == :member_role
    end

    # Role based AccessLevel records are evaluated differently from member_role based records.
    # records. If a role based AccessLevel record specifies an access_level,
    # any role with an access level equal or greater can perform the action.
    # Member role based AccessLevel records specify the member_role_id
    # which can perform the action.
    def member_role_access_allowed?(current_user, current_project)
      return false unless custom_roles_licensed?(current_project)
      return false unless member_role?

      member = find_member_for_user(current_user, current_project)
      return false unless member

      member.member_role_id == member_role.id
    end

    def find_member_for_user(current_user, current_project)
      if current_project
        find_member_for_user_for_project(current_user, current_project)
      elsif protected_ref_project
        find_member_for_user_for_project(current_user, protected_ref_project)
      elsif protected_branch_group
        protected_branch_group.members_with_parents.find_by(user_id: current_user.id)
      end
    end

    def find_member_for_user_for_project(current_user, project)
      # Check project membership first to prevent privilege escalation
      # where the user has a higher role or different custom role in
      # the group
      project.members.find_by(user: current_user) ||
        project.group&.members_with_parents&.find_by(user_id: current_user.id)
    end

    def validate_member_role_namespace
      unless custom_roles_licensed?
        errors.add(:member_role, 'is not licensed for the root namespace')
        return
      end

      return unless member_role

      root_namespace = protected_ref_project&.root_namespace || protected_branch_group&.root_ancestor
      return unless root_namespace

      return if member_role.namespace_id == root_namespace.id

      errors.add(:member_role, 'must belong to the same root namespace as the project or group')
    end
  end
end
