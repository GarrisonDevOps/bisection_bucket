# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Calls the session lifecycle hook a foundational flow declared, if any. Adding a
    # lifecycle point means a row in `Ai::Catalog::FoundationalFlow::SESSION_LIFECYCLE_HOOKS`
    # and a subscription, not a new worker.
    # Hook contract: doc/development/ai_features/foundational_flows.md.
    #
    # rubocop:disable Scalability/IdempotentWorker -- EventStore::Subscriber includes idempotent
    class SessionLifecycleWorker
      include Gitlab::EventStore::Subscriber

      feature_category :duo_agent_platform

      data_consistency :sticky
      urgency :high

      concurrency_limit -> { 100 }

      sidekiq_options retry: 3

      defer_on_database_health_signal :gitlab_main_org, [:duo_workflows_workflows]

      sidekiq_retries_exhausted do |job, exception|
        data = Array.wrap(job['args'].second).first.to_h

        Gitlab::AppLogger.error(
          message: 'Session lifecycle hook failed: retries exhausted',
          error_class: exception&.class&.name,
          event_class: job['args'].first,
          workflow_id: data.dig('data', 'workflow_id') || data['workflow_id']
        )
      end

      def handle_event(event)
        return unless ::Ai::Catalog::FoundationalFlow::SESSION_LIFECYCLE_HOOKS.key?(event.class)

        workflow_id = event.event_data[:workflow_id]

        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        unless workflow
          log_skip('session not found', event: event, workflow_id: workflow_id)
          return
        end

        flow = workflow.foundational_flow
        return unless flow
        return unless flow.run_session_hook(event.class, workflow: workflow)

        log_success(flow, event: event, workflow_id: workflow_id)
      end

      private

      def log_skip(reason, event:, workflow_id:)
        Gitlab::AppLogger.info(
          message: "Session lifecycle hook skipped: #{reason}",
          lifecycle_point: event.event_type.to_s,
          workflow_id: workflow_id
        )
      end

      def log_success(flow, event:, workflow_id:)
        Gitlab::AppLogger.info(
          message: 'Session lifecycle hook ran',
          foundational_flow_reference: flow.foundational_flow_reference,
          lifecycle_point: event.event_type.to_s,
          workflow_id: workflow_id
        )
      end
    end
    # rubocop:enable Scalability/IdempotentWorker
  end
end
