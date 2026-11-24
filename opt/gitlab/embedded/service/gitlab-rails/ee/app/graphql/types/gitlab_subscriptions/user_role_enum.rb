# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class UserRoleEnum < BaseEnum
      graphql_name 'GitlabSubscriptionsUserRole'
      description 'Role of User'

      value 'GUEST', value: :guest, description: 'Guest.'
      value 'PLANNER', value: :planner, description: 'Planner.'
      value 'REPORTER', value: :reporter, description: 'Reporter.'
      value 'SECURITY_MANAGER', value: :security_manager, description: 'Security manager access.'
      value 'DEVELOPER', value: :developer, description: 'Developer.'
      value 'MAINTAINER', value: :maintainer, description: 'Maintainer.'
      value 'OWNER', value: :owner, description: 'Owner.'
    end
  end
end
