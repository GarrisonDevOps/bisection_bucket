# frozen_string_literal: true

module Types
  module Members
    class PendingProjectMemberType < BaseObject
      graphql_name 'PendingProjectMember'
      description 'Represents a Pending Project Membership'

      authorize :admin_project_member
      authorize_granular_token permissions: :read_pending_member, boundary: :project, boundary_type: :project

      implements PendingMemberInterface
    end
  end
end
