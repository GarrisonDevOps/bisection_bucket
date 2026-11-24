# frozen_string_literal: true

module EE
  module Types
    module GitlabSubscriptions
      module MemberManagement
        class UsersQueuedForRolePromotionType < ::Types::BaseObject
          graphql_name 'UsersQueuedForRolePromotion'
          description 'Represents a Pending Member Approval Queued for Role Promotion'

          connection_type_class ::Types::CountableConnectionType

          field :new_access_level, ::Types::AccessLevelType, null: true,
            description: 'Highest New GitLab::Access level requested for the member.'

          field :user, ::Types::UserType, null: true,
            description: 'User that is associated with the member approval object.'
        end
      end
    end
  end
end
