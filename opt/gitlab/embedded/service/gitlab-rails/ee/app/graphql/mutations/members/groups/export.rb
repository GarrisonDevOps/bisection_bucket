# frozen_string_literal: true

module Mutations
  module Members
    module Groups
      class Export < BaseMutation
        graphql_name 'GroupMembersExport'
        authorize :export_group_memberships
        authorize_granular_token permissions: :read_member,
          boundary_argument: :group_id, boundary_type: :group

        argument :group_id,
          ::Types::GlobalIDType[::Group],
          required: true,
          description: 'Global ID of the group.'

        field :message, GraphQL::Types::String,
          null: true,
          description: 'Export request result message.'

        def resolve(args)
          group = authorized_find!(args[:group_id])

          raise_resource_not_available_error! unless Feature.enabled?(:members_permissions_detailed_export, group)

          ::Namespaces::Export::ExportRunner.new(group, current_user).execute

          {
            message: format(_('Your CSV export request has succeeded. The result will be emailed to %{email}.'),
              email: current_user.notification_email_or_default),
            errors: []
          }
        end

        private

        def find_object(id)
          GitlabSchema.object_from_id(id, expected_type: ::Group)
        end
      end
    end
  end
end
