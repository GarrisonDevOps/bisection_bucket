# frozen_string_literal: true

module MemberRoles
  module MemberRoleRelation
    extend ActiveSupport::Concern

    included do
      belongs_to :member_role

      validate :validate_member_role_access_level
      validate :validate_access_level_locked_for_member_role, on: :update
      validate :validate_member_role_belongs_to_same_root_namespace

      cattr_accessor :base_access_level_attr
      cattr_accessor :member_role_owner_association do
        :group
      end

      def self.base_access_level_attr(attr)
        self.base_access_level_attr = attr
      end

      def self.member_role_owner_association(name)
        self.member_role_owner_association = name
      end
    end

    def set_access_level_based_on_member_role
      if member_role && member_role_owner.custom_roles_enabled?
        self[base_access_level_attr] = member_role.base_access_level
      else
        self.member_role_id = nil
      end
    end

    def member_role_owner
      resource = try(member_role_owner_association)
      resource.is_a?(Namespace) ? resource : resource.try(:namespace)
    end

    private

    def validate_member_role_access_level
      return unless member_role_id && member_role_owner&.custom_roles_enabled?
      return if self[base_access_level_attr] == member_role.base_access_level

      errors.add(:member_role_id, _("the custom role's base access level does not match the current access level"))
    end

    def validate_access_level_locked_for_member_role
      return unless member_role_id && member_role_owner&.custom_roles_enabled?
      return if member_role_changed? # it is ok to change the access level when changing the member role
      return unless changed.include?(base_access_level_attr.to_s)

      errors.add(base_access_level_attr,
        _('cannot be changed because of an existing association with a custom role'))
    end

    def validate_member_role_belongs_to_same_root_namespace
      return unless member_role_id && member_role_owner.custom_roles_enabled?
      return unless member_role.namespace_id

      return if member_role_owner.id == member_role.namespace_id
      return if member_role_owner.root_ancestor.id == member_role.namespace_id

      errors.add(member_role_owner_association, _("must be in same hierarchy as custom role's namespace"))
    end
  end
end
