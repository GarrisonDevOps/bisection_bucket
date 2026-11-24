# frozen_string_literal: true

module EE
  module Types
    module GitlabSubscriptions
      module MemberManagement
        class UserPromotionStatusEnum < ::Types::BaseEnum
          graphql_name 'UserPromotionStatusType'
          description 'Types of User Promotion States.'

          value 'SUCCESS', value: :success,
            description: 'Successfully applied all promotion requests for user.'
          value 'PARTIAL_SUCCESS', value: :partial_success,
            description: 'User promotion was successful, but all promotion requests were not successfully applied.'
          value 'FAILED', value: :failed,
            description: 'Failed to apply promotion requests for user.'
        end
      end
    end
  end
end
