# frozen_string_literal: true

module Mutations
  module MemberRoles
    class Base < ::Mutations::BaseMutation
      include ::GitlabSubscriptions::SubscriptionHelper

      field :member_role,
        ::Types::MemberRoles::MemberRoleType,
        description: 'Member role.',
        null: true

      argument :description,
        GraphQL::Types::String,
        required: false,
        description: 'Description of the member role.'

      argument :name,
        GraphQL::Types::String,
        required: false,
        description: 'Name of the member role.'

      argument :permissions,
        [Types::MemberRoles::PermissionsEnum],
        required: false,
        description: 'List of all customizable permissions.'

      private

      def canonicalize_for_create(args)
        permissions = args.delete(:permissions) || []
        permissions.each_with_object(args) do |permission, new_args|
          new_args[permission.downcase] = true
        end
      end

      def canonicalize_for_update(args, available_permissions: MemberRole.all_customizable_standard_permissions.keys)
        permissions = args.delete(:permissions) || []
        permissions.each_with_object(args) do |permission, new_args|
          new_args[permission.downcase] = true
        end

        (available_permissions - permissions).each_with_object(args) do |permission, new_args|
          new_args[permission.downcase] = false
        end
      end
    end
  end
end
