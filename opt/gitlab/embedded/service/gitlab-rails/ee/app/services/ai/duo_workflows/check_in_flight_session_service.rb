# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CheckInFlightSessionService
      include ::Services::ReturnServiceResponses
      include ::Gitlab::Loggable
      include ::Gitlab::Utils::StrongMemoize
      include ::Gitlab::ExclusiveLeaseHelpers

      LEASE_TTL = 30.seconds
      # The lease covers only the insert, so a concurrent request waits for it instead of being refused.
      LEASE_RETRIES = 5
      LEASE_SLEEP = 0.1.seconds

      def initialize(workflow:)
        @workflow = workflow
        @superseded_sessions = []
      end

      # Yields to save the session. The block and this method return an error response, or nil.
      def execute
        return yield unless guarded?

        in_lock(lease_key, ttl: LEASE_TTL, retries: LEASE_RETRIES, sleep_sec: LEASE_SLEEP) do
          claim { yield }
        end
      rescue FailedToObtainLockError
        in_flight_error(nil)
      end

      # Stops the live sessions the saved session supersedes. Call it after the creation checks, so a
      # session they drop leaves the older ones running. A later failure to start in CI does not.
      def supersede_live_sessions
        superseded_sessions.each { |session| supersede(session) }

        nil
      end

      private

      attr_reader :workflow, :superseded_sessions

      def claim
        live = in_flight_sessions.live
        holder = in_flight_sessions.covering
        holder ||= live.first unless flow.concurrency.supersede?
        holder ||= live.find { |session| !stoppable_by_requester?(session) }
        return in_flight_error(holder) if holder

        revision = in_flight_sessions.revision
        workflow.flow_metadata_json = FlowMetadata.with_revision(workflow.flow_metadata_json, revision)

        save_error = yield
        return save_error if save_error

        @superseded_sessions = live

        nil
      end

      def guarded?
        flow&.concurrency&.declared? &&
          resource.present? &&
          flow.supports_resource?(resource) &&
          flow.concurrency.enabled_for?(workflow.resource_parent) &&
          !workflow.executed_by_client? &&
          workflow.messaging_callback_adapter.nil?
      end

      def in_flight_sessions
        InFlightSessions.new(flow: flow, resource: resource)
      end
      strong_memoize_attr :in_flight_sessions

      def stoppable_by_requester?(session)
        Ability.allowed?(workflow.user, :update_duo_workflow, session) ||
          Ability.allowed?(workflow.user, :stop_duo_workflow, session)
      end

      def supersede(session)
        result = ::Ai::DuoWorkflows::UpdateWorkflowStatusService.new(
          workflow: session.reset,
          status_event: 'stop',
          current_user: workflow.user
        ).execute
        return if result.success?

        log_not_superseded(session, result.message)
      rescue StandardError => error
        ::Gitlab::ErrorTracking.track_exception(error, workflow_id: session.id, superseded_by_workflow_id: workflow.id)
        log_not_superseded(session, error.message)
      end

      def log_not_superseded(session, error_message)
        ::Gitlab::AppLogger.warn(
          build_structured_payload_labkit(
            message: 'Duo session not superseded',
            ::Labkit::Fields::ERROR_MESSAGE => error_message,
            ::Labkit::Fields::DUO_WORKFLOW_ID => session.id,
            superseded_by_workflow_id: workflow.id
          )
        )
      end

      def in_flight_error(holder)
        ::Gitlab::AppLogger.info(
          build_structured_payload_labkit(
            message: 'Duo session refused: a live session holds the resource',
            ::Labkit::Fields::DUO_WORKFLOW_DEFINITION => workflow.workflow_definition,
            live_workflow_id: holder&.id
          )
        )

        error('A session of this flow is already running for this resource.', :conflict,
          pass_back: { reason: :session_in_flight, workflow_id: holder&.id }.compact)
      end

      def lease_key
        "duo_workflows:live_session:#{workflow.workflow_definition}:#{resource.class.name}:#{resource.id}"
      end

      def flow
        workflow.foundational_flow
      end

      def resource
        workflow.resource
      end
      strong_memoize_attr :resource
    end
  end
end
