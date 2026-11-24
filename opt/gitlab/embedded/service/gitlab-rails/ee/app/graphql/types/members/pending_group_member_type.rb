# frozen_string_literal: true

module Types
  module Members
    class PendingGroupMemberType < BaseObject
      graphql_name 'PendingGroupMember'
      description 'Represents a Pending Group Membership'

      authorize :admin_group_member
      authorize_granular_token permissions: :read_pending_member, boundary: :group, boundary_type: :group

      implements PendingMemberInterface
    end
  end
end
