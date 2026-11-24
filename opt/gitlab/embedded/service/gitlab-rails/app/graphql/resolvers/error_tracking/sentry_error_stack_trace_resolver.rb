# frozen_string_literal: true

module Resolvers
  module ErrorTracking
    class SentryErrorStackTraceResolver < BaseResolver
      include SentryFieldCallLimit

      type Types::ErrorTracking::SentryErrorStackTraceType, null: true

      limit_sentry_field_calls 1

      argument :id, ::Types::GlobalIDType[::Gitlab::ErrorTracking::DetailedError],
        required: true,
        description: 'ID of the Sentry issue.'

      def resolve(id:)
        # Get data from Sentry
        response = ::ErrorTracking::IssueLatestEventService.new(
          project,
          current_user,
          { issue_id: id.model_id }
        ).execute

        raise_resource_not_available_error!(response[:message]) if response[:http_status] == :too_many_requests

        event = response[:latest_event]
        event.gitlab_project = project if event

        event
      end

      private

      def project
        return object.gitlab_project if object.respond_to?(:gitlab_project)

        object
      end
    end
  end
end
