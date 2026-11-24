# frozen_string_literal: true

module Subscriptions
  module Security
    class PolicyProjectCreated < ::Subscriptions::BaseSubscription
      include Gitlab::Graphql::Laziness

      payload_type Types::GitlabSubscriptions::Security::PolicyProjectCreated

      argument :full_path, GraphQL::Types::String,
        required: true,
        description: 'Full path of the project or group.'

      def authorized?(args)
        container = Routable.find_by_full_path(args[:full_path])

        Ability.allowed?(current_user, :update_security_orchestration_policy_project, container)
      end

      def update(_)
        {
          project: object[:project],
          status: object[:status],
          errors: object[:errors],
          error_message: object[:error_message]
        }
      end
    end
  end
end
