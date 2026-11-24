# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # Stops the fix loop when a Duo Developer fix run ends without a push. A session hook of the Developer flow
      # does not fit: the loop belongs to the flow trigger, and the hooks run in a high urgency worker.
      #
      # rubocop:disable Scalability/IdempotentWorker -- EventStore::Subscriber includes idempotent
      class FixRunEndedWorker
        include Gitlab::EventStore::Subscriber

        feature_category :dap_triggers
        data_consistency :sticky
        urgency :low

        concurrency_limit -> { 100 }

        # The job makes few writes for each event, so it waits only for load on the whole database. Autovacuum of
        # the large merge_requests and notes tables can run for hours, and the author must get the note soon.
        defer_on_database_health_signal :gitlab_main_org,
          indicators: ::Gitlab::Database::HealthStatus::GLOBAL_INDICATORS

        # The job writes as the service account of the trigger. An inherited identity of the session would make
        # the permission checks also check the human of the session.
        skip_composite_identity_passthrough!

        # The subscription filter. It reads the flow from the payload first, so the end of a session of another
        # flow costs no query.
        def self.dispatch?(event)
          return false unless event.event_data[:workflow_definition] == FixLoop.developer_reference

          fix_run = ::Ai::DuoWorkflows::Workflow.find_by_id(event.event_data[:workflow_id])
          return false unless fix_run
          return false unless fix_run.trigger_flow_trigger_id && fix_run.merge_request_id
          return false unless fix_run.trigger_event_merge_request?

          feature_enabled?(fix_run)
        end

        def self.feature_enabled?(fix_run)
          ::Gitlab::Ai::SoftwareFactory.enabled?(fix_run.project)
        end

        def handle_event(event)
          fix_run = ::Ai::DuoWorkflows::Workflow.find_by_id(event.event_data[:workflow_id])
          # A retried session runs again, and its next end publishes another event.
          return unless fix_run&.status_terminal?
          return unless self.class.feature_enabled?(fix_run)

          result = FixRunEndedService.new(fix_run).execute
          return if result.success?

          logger.info(structured_payload(message: "Fix loop not stopped: #{result.message}",
            reason: result.reason, Labkit::Fields::DUO_WORKFLOW_ID => fix_run.id,
            merge_request_id: fix_run.merge_request_id))
        end
      end
      # rubocop:enable Scalability/IdempotentWorker
    end
  end
end
