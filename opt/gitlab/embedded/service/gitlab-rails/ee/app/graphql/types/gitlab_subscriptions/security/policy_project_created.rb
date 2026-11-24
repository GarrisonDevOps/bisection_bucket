# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module Security
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization will be handled in subscription
      class PolicyProjectCreated < ::Types::BaseObject
        graphql_name 'PolicyProjectCreated'
        description 'Response of security policy creation.'

        # Returned only by Subscription.securityPolicyProjectCreated, which requires read_security_policy
        # on the project or group. The project authorizes itself.
        authorize_granular_token parent_authorizes: :read_security_policy

        field :project, Types::ProjectType,
          null: true,
          description: 'Security Policy Project that was created.'

        field :status, Types::GitlabSubscriptions::Security::PolicyProjectCreatedStatusEnum,
          description: 'Status of the creation of the security policy project.'

        field :errors, [GraphQL::Types::String],
          null: true,
          description: 'Error messages in case status is :error.'

        field :error_message, GraphQL::Types::String,
          null: true,
          description: 'Error messages in case status is :error.',
          deprecated: { milestone: '17.5', reason: 'Use errors instead' }
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
