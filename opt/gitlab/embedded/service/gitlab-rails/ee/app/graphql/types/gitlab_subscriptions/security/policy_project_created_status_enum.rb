# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module Security
      class PolicyProjectCreatedStatusEnum < ::Types::BaseEnum
        graphql_name 'PolicyProjectCreatedStatus'
        description 'Types of security policy project created status.'

        value 'SUCCESS', value: :success, description: 'Creating the security policy project was successful.'
        value 'ERROR', value: :error, description: 'Creating the security policy project failed.'
      end
    end
  end
end
