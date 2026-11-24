# frozen_string_literal: true

module Mutations
  module MemberRoles
    class Create < Base
      graphql_name 'MemberRoleCreate'

      include Mutations::ResolvesNamespace

      authorize :admin_member_role
      authorize_granular_token permissions: :create_member_role,
        boundaries: [
          { boundary_argument: :group_path, boundary_type: :group, assignable_when: [:saas] },
          { boundary: :instance, boundary_type: :instance, assignable_when: [:admin, :self_managed] }
        ]

      argument :base_access_level,
        ::Types::Members::MemberRoles::AccessLevelEnum,
        required: true,
        description: 'Base access level for the custom role.'

      argument :group_path, GraphQL::Types::ID,
        required: false,
        description: 'Group the member role to mutate is in. Required for SaaS.'

      def ready?(**args)
        raise Gitlab::Graphql::Errors::ArgumentError, 'group_path argument is required.' if missing_group_path?(args)

        if extra_group_path?(args)
          raise Gitlab::Graphql::Errors::ArgumentError, 'group_path argument is not allowed on self-managed instances.'
        end

        super
      end

      def resolve(**args)
        group = find_group(args.delete(:group_path))

        params = canonicalize_for_create(args.merge(namespace: group))
        response = ::MemberRoles::CreateService.new(current_user, params).execute

        raise_resource_not_available_error! if response.error? && response.reason == :unauthorized

        {
          member_role: response.payload,
          errors: response.errors
        }
      end

      private

      def find_group(group_path)
        return unless group_path

        group = ::Gitlab::Graphql::Lazy.force(find_object(group_path: group_path))

        raise_resource_not_available_error! unless group

        group
      end

      def find_object(group_path:)
        resolve_namespace(full_path: group_path)
      end

      def missing_group_path?(args)
        return false unless gitlab_com_subscription?

        args[:group_path].blank?
      end

      def extra_group_path?(args)
        return false if gitlab_com_subscription?

        args[:group_path].present?
      end
    end
  end
end
