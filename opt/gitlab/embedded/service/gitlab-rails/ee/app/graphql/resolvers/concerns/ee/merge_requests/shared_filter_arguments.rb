# frozen_string_literal: true

module EE
  module MergeRequests
    module SharedFilterArguments
      extend ActiveSupport::Concern

      included do
        argument :approver, [GraphQL::Types::String],
          required: false,
          as: :approver_usernames,
          description: 'Usernames of possible approvers.'
      end
    end
  end
end
