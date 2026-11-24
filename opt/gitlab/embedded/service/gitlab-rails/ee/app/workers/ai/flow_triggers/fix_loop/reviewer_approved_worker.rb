# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # Tells the author that the merge request is ready for the final review when the reviewer of a fix loop
      # approves it.
      #
      # rubocop:disable Scalability/IdempotentWorker -- EventStore::Subscriber includes idempotent
      class ReviewerApprovedWorker
        include Gitlab::EventStore::Subscriber

        feature_category :dap_triggers
        data_consistency :sticky
        urgency :low

        concurrency_limit -> { 100 }

        # The job makes few writes for each event, so it waits only for load on the whole database. Autovacuum of
        # the large merge_requests and notes tables can run for hours, and the author must get the note soon.
        defer_on_database_health_signal :gitlab_main_org,
          indicators: ::Gitlab::Database::HealthStatus::GLOBAL_INDICATORS

        # The job writes as the service account of the trigger. An approval made under a composite identity would
        # otherwise be inherited by the job, and the permission checks would also check the human of that session.
        skip_composite_identity_passthrough!

        # The subscription filter. No job is queued while the flag is off, so a Sidekiq node without this worker gets
        # none during the first deploy.
        def self.dispatch?(event)
          project_id = event.event_data[:project_id]
          return false unless ::Ai::FlowTrigger.registered_for?(project_id, :merge_request)

          project = ::Project.find_by_id(project_id)
          return false unless project

          feature_enabled?(project)
        end

        def self.feature_enabled?(project)
          ::Gitlab::Ai::SoftwareFactory.enabled?(project)
        end

        def handle_event(event)
          merge_request = MergeRequest.find_by_id(event.event_data[:merge_request_id])
          return unless merge_request
          return unless self.class.feature_enabled?(merge_request.target_project)

          reviewer = event.current_user
          return unless reviewer

          result = ReviewerApprovedService.new(merge_request,
            reviewer: reviewer, approved_at: Time.zone.parse(event.event_data[:approved_at])).execute
          return if result.success?

          logger.info(structured_payload(message: "Fix loop ready note not added: #{result.message}",
            reason: result.reason, merge_request_id: merge_request.id))
        end
      end
      # rubocop:enable Scalability/IdempotentWorker
    end
  end
end
