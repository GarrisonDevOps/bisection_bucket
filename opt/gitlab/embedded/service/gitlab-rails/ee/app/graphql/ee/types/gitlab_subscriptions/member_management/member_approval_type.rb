# frozen_string_literal: true

module EE
  module Types
    module GitlabSubscriptions
      module MemberManagement
        class MemberApprovalType < ::Types::BaseObject
          graphql_name 'MemberApproval'
          description 'Represents a Member Approval queued for role promotion.'

          connection_type_class ::Types::CountableConnectionType

          field :new_access_level, ::Types::AccessLevelType, null: true,
            description: 'New GitLab::Access level requested for the member.'

          field :user, ::Types::UserType, null: true,
            description: 'User that is associated with the member approval object.'

          field :old_access_level, ::Types::AccessLevelType, null: true,
            description: 'Existing GitLab::Access level for the member.'

          field :requested_by, ::Types::UserType, null: true,
            description: 'User who requested the member promotion.'

          field :reviewed_by, ::Types::UserType, null: true,
            description: 'User who reviewed the member promotion.'

          field :status, GraphQL::Types::String, null: true,
            description: 'Status for the member approval request (approved, denied, pending).'

          field :created_at, ::Types::TimeType, null: true,
            description: 'Timestamp when the member approval was created.'

          field :updated_at, ::Types::TimeType, null: true,
            description: 'Timestamp when the member approval was last updated.'

          field :member_role_id, ::GraphQL::Types::ID, null: true,
            description: 'ID of the member role.'

          field :member, ::Types::MemberInterface, null: true,
            description: 'Member associated with the member approval object.'
        end
      end
    end
  end
end
