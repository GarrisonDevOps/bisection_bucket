# frozen_string_literal: true

module Resolvers
  module CloudConnector
    class StatusResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::CloudConnector::StatusType, null: false

      description 'Run a series of status checks for Cloud Connector features'

      def resolve
        raise_resource_not_available_error! unless can_read_cloud_connector_status?

        ::CloudConnector::StatusChecks::StatusService.new(user: current_user).execute
      end

      private

      def can_read_cloud_connector_status?
        return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        Ability.allowed?(current_user, :read_cloud_connector_status)
      end
    end
  end
end
