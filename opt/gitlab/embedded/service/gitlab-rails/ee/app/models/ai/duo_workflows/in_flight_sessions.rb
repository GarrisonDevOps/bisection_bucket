# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class InFlightSessions
      include ::Gitlab::Utils::StrongMemoize

      def initialize(flow:, resource:)
        @flow = flow
        @resource = resource
      end

      def live
        sessions = ::Ai::DuoWorkflows::Workflow
          .with_workflow_definition(flow.foundational_flow_reference)
          .without_messaging_sessions
          .without_client_executed
          .with_status(*flow.concurrency.live_statuses)

        sessions = resource.is_a?(::MergeRequest) ? sessions.for_merge_request(resource) : sessions.for_issue(resource)

        # A replica can lag behind the session another request just created.
        ::Gitlab::Database::LoadBalancing::SessionMap.current(::Ai::DuoWorkflows::Workflow.load_balancer)
          .use_primary { sessions.to_a }
      end
      strong_memoize_attr :live

      # The live session that already covers the resource's current revision, if any.
      def covering
        live.find { |session| covers?(session) }
      end

      def revision
        flow.concurrency.revision_for(resource)
      end
      strong_memoize_attr :revision

      private

      attr_reader :flow, :resource

      def covers?(session)
        return true unless flow.concurrency.tracks_revision?

        covered = FlowMetadata.revision(session.flow_metadata_json)
        covered.nil? || revision.nil? || covered == revision
      end
    end
  end
end
