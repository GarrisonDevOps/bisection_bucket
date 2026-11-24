# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class ExecuteMergeRequestRequestedChangesWorkflowTriggersWorker
        include Ai::CloudEventsFlowTriggerWorker
        include Ai::MergeRequestFlowTriggerFilterData
        include Gitlab::ExclusiveLeaseHelpers

        concurrency_limit -> { 100 }
        idempotent!

        LEASE_TTL = ::Ai::FlowTriggers::FixLoop::LEASE_TTL
        LeaseTakenError = ::Ai::FlowTriggers::FixLoop::LeaseTakenError

        # nil falls through to Sidekiq's own exponential backoff.
        sidekiq_retry_in do |_count, exception|
          LEASE_TTL.to_i if exception.is_a?(LeaseTakenError)
        end

        class << self
          def cloud_event_class
            MergeRequests::RequestedChangesCloudEvent
          end

          def event_type
            :merge_request
          end

          def action
            'requested_changes'
          end
        end

        private

        def find_resource_and_container(cloud_event)
          merge_request = MergeRequest.find_by_id(cloud_event.event_data[:merge_request_id])

          unless merge_request
            logger.info(structured_payload(message: 'Merge request not found.',
              merge_request_id: cloud_event.event_data[:merge_request_id]))
            return
          end

          [merge_request, merge_request.target_project]
        end

        def feature_enabled?(project)
          ::Gitlab::Ai::SoftwareFactory.enabled?(project)
        end

        # A Duo Code Review verdict has no composite actor in the envelope, so it looks like a human verdict.
        def originated_from_flow?(cloud_event)
          super || review_verdict?(cloud_event)
        end

        def chaining_enabled?(cloud_event, container)
          return super unless review_verdict?(cloud_event)

          Feature.enabled?(:ai_flow_trigger_chaining, container.root_ancestor)
        end

        # The envelope of a Duo Code Review verdict names no session, so the log names the review session.
        def log_flow_originated_skip(cloud_event, message)
          return super unless review_verdict?(cloud_event)

          logger.info(structured_payload(message: message,
            reason: :non_human_trigger_not_permitted,
            Labkit::Fields::DUO_WORKFLOW_ID => cloud_event.event_data[:review_workflow_id]))
        end

        # The event user is the review bot, which does not own the review session. Only Duo Code Review
        # sets `review_workflow_id`, so the session is trusted for a verdict of the bot on this merge request.
        def resolve_parent_workflow(cloud_event, merge_request)
          return super unless review_verdict?(cloud_event)
          return unless cloud_event.current_user.duo_code_review_bot?

          ::Ai::DuoWorkflows::Workflow
            .for_project(merge_request.target_project)
            .for_merge_request(merge_request)
            .with_workflow_definition(::Ai::Catalog::FoundationalFlow.code_review_v1.foundational_flow_reference)
            .without_messaging_sessions
            .find_by_id(cloud_event.event_data[:review_workflow_id])
        end

        # A later review can replace the verdict before this job runs.
        def passes_event_checks?(cloud_event, merge_request)
          return true if merge_request.find_reviewer(cloud_event.current_user)&.requested_changes?

          logger.info(structured_payload(message: 'Reviewer no longer requests changes.',
            merge_request_id: merge_request.id))

          false
        end

        # One verdict can publish the event twice, for example when PublishCommentsWorker retries, and a human can
        # submit two verdicts close together. One job at a time for each merge request, so the checks see the run
        # that the last job started. A job that cannot get the lock retries.
        def execute_flow_triggers(resource, container, current_user, cloud_event, parent_workflow)
          in_lock(lease_key(resource), ttl: LEASE_TTL, retries: 0) { super }
        rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
          raise LeaseTakenError, "Another job holds the lease for merge request #{resource.id}."
        end

        # Checked for each flow trigger, so a retried job still starts the flow triggers that did not start.
        def passes_trigger_checks?(flow_trigger, cloud_event, merge_request, parent_workflow)
          if review_verdict?(cloud_event) && already_ran?(flow_trigger, parent_workflow)
            logger.info(structured_payload(message: 'Flow trigger already ran for this review verdict.',
              flow_trigger_id: flow_trigger.id,
              Labkit::Fields::DUO_WORKFLOW_ID => parent_workflow.id))

            return false
          end

          return true unless ::Ai::FlowTriggers::FixLoop.applies_to?(flow_trigger)

          passes_fix_loop_checks?(flow_trigger, cloud_event, merge_request)
        end

        # A second event for the same verdict finds the merge request a draft, so a stopped loop gets one note.
        def passes_fix_loop_checks?(flow_trigger, cloud_event, merge_request)
          result = fix_loop_check(flow_trigger, cloud_event, merge_request)
          return true if result.success?

          logger.info(structured_payload(message: result.message, reason: result.reason,
            flow_trigger_id: flow_trigger.id, merge_request_id: merge_request.id))

          case result.reason
          when :max_fix_runs
            stop_fix_loop(flow_trigger, merge_request, :max_fix_runs,
              reviewer: cloud_event.current_user, max_fix_runs: result.payload[:config].max_fix_runs)
          when :invalid_config
            stop_fix_loop(flow_trigger, merge_request, :invalid_config, errors: result.payload[:config].errors)
          when :check_failed
            stop_fix_loop(flow_trigger, merge_request, :fix_run_not_started)
          end

          false
        end

        # A check that raises, for example when Gitaly cannot read the configuration, stops the loop as a run that
        # raises does. Otherwise the loop stops without a note. The configuration comes before the label and reviewer
        # gates, so a failed read stops the loop for any verdict.
        def fix_loop_check(flow_trigger, cloud_event, merge_request)
          ::Ai::FlowTriggers::FixLoop::Check.new(merge_request,
            reviewer: cloud_event.current_user, verdict_at: Time.iso8601(cloud_event.data[:time])).execute
        rescue StandardError => error
          ::Gitlab::ErrorTracking.track_exception(error, flow_trigger_id: flow_trigger.id,
            merge_request_id: merge_request.id)
          ServiceResponse.error(message: 'Fix loop check raised an error.', reason: :check_failed)
        end

        def after_flow_trigger_run(flow_trigger, merge_request, response)
          return unless response&.error? && ::Ai::FlowTriggers::FixLoop.applies_to?(flow_trigger)

          stop_fix_loop(flow_trigger, merge_request, :fix_run_not_started)
        end

        def stop_fix_loop(flow_trigger, merge_request, reason, **details)
          ::Ai::FlowTriggers::FixLoop.add_inherited_service_account(flow_trigger, merge_request.target_project)

          ::Ai::FlowTriggers::FixLoop::StopService.new(merge_request,
            service_account: flow_trigger.service_account, reason: reason, details: details).execute
        end

        # The goal of a fix run names the reviewer whose threads it answers.
        def additional_run_params(cloud_event, _merge_request)
          { reviewer_username: cloud_event.current_user.username }
        end

        # A replica can miss the run that the job of the first event started.
        def already_ran?(flow_trigger, review_workflow)
          ::Gitlab::Database::LoadBalancing::SessionMap.current(review_workflow.load_balancer).use_primary do
            review_workflow.child_workflows.trigger_event_merge_request.for_flow_triggers([flow_trigger]).exists?
          end
        end

        def review_verdict?(cloud_event)
          cloud_event.event_data[:review_workflow_id].present? || cloud_event.current_user&.duo_code_review_bot?
        end

        def lease_key(merge_request)
          ::Ai::FlowTriggers::FixLoop.lease_key(merge_request)
        end
      end
    end
  end
end
