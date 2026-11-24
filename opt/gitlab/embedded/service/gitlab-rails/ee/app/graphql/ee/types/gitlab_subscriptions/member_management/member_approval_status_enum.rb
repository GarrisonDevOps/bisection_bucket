# frozen_string_literal: true

module EE
  module Types
    module GitlabSubscriptions
      module MemberManagement
        class MemberApprovalStatusEnum < ::Types::BaseEnum
          graphql_name 'MemberApprovalStatusType'
          description 'Types of member approval status.'

          value 'APPROVED', value: :approved, description: 'Approved promotion request.'
          value 'DENIED', value: :denied, description: 'Denied promotion request.'
          value 'PENDING', value: :pending, description: 'Pending promotion request.'
        end
      end
    end
  end
end
