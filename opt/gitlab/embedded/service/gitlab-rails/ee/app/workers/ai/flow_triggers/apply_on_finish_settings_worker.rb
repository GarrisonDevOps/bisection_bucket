# frozen_string_literal: true

module Ai
  module FlowTriggers
    # Applies the on-finish settings of the trigger that started a finished session.
    # Writes as the session's composite identity, so the trigger workers treat the
    # status change as flow-caused and apply their chaining rules to it.
    #
    # rubocop:disable Scalability/IdempotentWorker -- EventStore::Subscriber includes idempotent
    class ApplyOnFinishSettingsWorker
      include Gitlab::EventStore::Subscriber

      feature_category :dap_triggers
      data_consistency :sticky
      urgency :low

      concurrency_limit -> { 100 }

      # The job sets the session's identity itself; an inherited one would conflict with it.
      skip_composite_identity_passthrough!

      # The job makes few writes for each session, so it waits only for load on the whole database. Autovacuum of
      # the large issues and merge_requests tables can run for hours, and the next stage must start soon.
      defer_on_database_health_signal :gitlab_main_org,
        indicators: ::Gitlab::Database::HealthStatus::GLOBAL_INDICATORS

      # The subscription filter: only sessions that a trigger started, with the flag enabled.
      def self.dispatch?(event)
        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(event.event_data[:workflow_id])
        return false unless workflow&.trigger_flow_trigger_id

        feature_enabled?(workflow)
      end

      def self.feature_enabled?(workflow)
        ::Gitlab::Ai::SoftwareFactory.enabled?(workflow.resource_parent)
      end

      # With bounded chaining, the finished session becomes the parent of the session that the status change
      # starts. Without it, the change starts no session.
      def self.chaining_enabled?(workflow)
        Feature.enabled?(:ai_flow_trigger_chaining, root_ancestor(workflow))
      end

      def self.root_ancestor(workflow)
        workflow.resource_parent.root_ancestor
      end
      private_class_method :root_ancestor

      def handle_event(event)
        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(event.event_data[:workflow_id])
        return unless workflow&.finished?

        trigger = workflow.trigger_flow_trigger
        return unless trigger&.applies_on_finish?
        return unless self.class.feature_enabled?(workflow)

        reason = skip_reason(workflow, trigger)
        return log(workflow, trigger, message: "On-finish settings skipped: #{reason}") if reason

        as_session(workflow) do
          # Before the status: once the status moves, the work item no longer matches the filter,
          # so a retry after a failed merge request write would skip the merge requests.
          ready = trigger.ready_merge_requests_on_finish? ? mark_merge_requests_ready(workflow, trigger) : true
          next unless trigger.status_on_finish.present?

          # The next stage expects reviewable merge requests, so a Draft left behind holds the status.
          next set_status(workflow, trigger) if ready

          log(workflow, trigger, message: 'On-finish status not set: a merge request is still a Draft')
        end
      end

      private

      def skip_reason(workflow, trigger)
        return 'the trigger is inactive' unless trigger.active?
        return 'a work item event did not start the session' unless workflow.trigger_event_work_item?
        return 'flow trigger chaining is disabled' unless self.class.chaining_enabled?(workflow)

        unless chain_started_by_human?(workflow)
          return 'the session chain did not start from a human mention, assignment, work item event, merge, ' \
            'or chat session'
        end

        return 'the session has no work item' unless workflow.work_item
        return 'the session has no composite identity' unless workflow.service_account&.composite_identity_enforced?

        'the work item no longer matches the trigger filter' unless still_matches_filter?(workflow, trigger)
      end

      # A system event, such as a merge conflict, starts a session as a user who did not act. The walk starts
      # here because the status change makes this session the parent of the next one.
      def chain_started_by_human?(workflow)
        root = ::Ai::FlowTriggers::CallerContext.new(parent_workflow: workflow).root_workflow
        return false unless root&.triggered_by_human? && root.user.human?
        return true if ::Ai::FlowTrigger::HUMAN_ACTION_EVENT_TYPES.include?(root.trigger_event_type)
        return merged_by_human?(root) if root.trigger_event_merge_request?

        # A human writes to a chat session, and a flow that the chat starts is its child. No system process creates
        # a chat session with the human trigger source; a system process added later must set another one.
        root.trigger_event_type.nil? && root.chat?
      end

      # A session on the merged action runs as the author, who did not act, so the check needs a human who merged.
      # The session does not record its action, so only a session that started after the merge counts. Every other
      # merge_request action runs as the user who acted, so its late session is still a human start.
      def merged_by_human?(root)
        merge_request = root.merge_request
        return false unless merge_request&.merged?

        # GitLab finds a merge in a push, for example from a mirror update or a CI job, and records its source. The
        # pusher is then recorded as the user who merged, but no user merged the merge request in GitLab.
        return false if merge_request.merge_source

        metrics = merge_request.metrics
        return false unless metrics&.merged_at && root.created_at >= metrics.merged_at

        merged_by = metrics.merged_by
        merged_by.present? && merged_by.human?
      end

      # A human or another flow can move the work item while the session runs. A trigger with
      # on-finish settings starts only on Status changed, so the filter is checked for that action.
      def still_matches_filter?(workflow, trigger)
        work_item = workflow.work_item
        data = {
          'action' => 'status_changed',
          'status' => { 'name' => work_item.status_with_fallback&.name },
          'work_item_type_id' => work_item.work_item_type_id,
          'software_factory_enabled' => work_item.ai_planning_enabled?
        }

        ::Ai::FlowTriggers::FilterEvaluator.new(flow_trigger: trigger, hook_scope: :work_item, data: data).allowed?
      end

      # Links the session's identity for the block only. Restoring the request store also drops the
      # permission results cached while the identity was linked.
      def as_session(workflow, &block)
        saved = request_store_snapshot

        begin
          ::Gitlab::Auth::Identity.link_from_scoped_user(
            workflow.service_account, workflow.user, context: :authentication
          )
          ::Gitlab::ApplicationContext.with_context(duo_workflow_id: workflow.id.to_s, &block)
        ensure
          ::Gitlab::SafeRequestStore.storage.replace(saved)
        end
      end

      # The identity code adds to a Set in place, so copy each Set.
      def request_store_snapshot
        ::Gitlab::SafeRequestStore.storage.transform_values { |value| value.is_a?(Set) ? value.dup : value }
      end

      # Returns false when a Draft merge request that the session created stays a Draft.
      def mark_merge_requests_ready(workflow, trigger)
        all_ready = true

        workflow.merge_request_links.link_type_created.find_each do |link|
          merge_request = link.merge_request
          next unless merge_request.opened? && merge_request.draft?

          reason = not_ready_reason(workflow, merge_request)
          if reason
            log(workflow, trigger, message: "On-finish merge request not marked as ready: #{reason}",
              merge_request_id: merge_request.id)
            all_ready = false
            next
          end

          result = ::MergeRequests::UpdateService.new(
            project: merge_request.target_project,
            current_user: workflow.user,
            params: { wip_event: 'ready' }
          ).execute(merge_request)

          # On a failed save the in-memory title is already draftless, so check the errors.
          all_ready = false if result.errors.any?
          message = result.errors.any? ? 'not marked as ready' : 'marked as ready'
          log(workflow, trigger, message: "On-finish merge request #{message}", merge_request_id: merge_request.id,
            errors: result.errors.full_messages.join(', ').presence)
        end

        all_ready
      end

      def not_ready_reason(workflow, merge_request)
        # ProcessAutoMergeFromEventWorker, which the ready change starts, inherits the session identity, so a merge
        # set by the session's user runs as the service account. The merge request stays a Draft until the user
        # who set auto-merge marks it as ready.
        return 'auto-merge is set' if merge_request.auto_merge_enabled?

        # With the session's identity linked, this checks the service account and the human.
        'not allowed' unless Ability.allowed?(workflow.service_account, :update_merge_request, merge_request)
      end

      def set_status(workflow, trigger)
        work_item = workflow.work_item

        # The same permission that the status callback checks, here for both identities.
        unless Ability.allowed?(workflow.service_account, :set_work_item_metadata, work_item)
          return log(workflow, trigger, message: 'On-finish status not set: not allowed')
        end

        # One write per finished session as the user who started the chain, so a throttled user would
        # only make this job fail and retry. The work item update limit is for requests, not jobs.
        result = ::WorkItems::UpdateService.new(
          container: work_item.resource_parent,
          current_user: workflow.user,
          params: {},
          widget_params: { status_widget: { name: trigger.status_on_finish } }
        ).execute_without_rate_limiting(work_item)

        # The status callback ignores a status it cannot apply and still reports success.
        applied = ::WorkItem.find_by_id(work_item.id)&.status_with_fallback&.name
        set = applied.to_s.casecmp?(trigger.status_on_finish)
        log(workflow, trigger,
          message: set ? 'On-finish status set' : 'On-finish status not set',
          status: trigger.status_on_finish, current_status: applied,
          errors: Array(result[:message]).join(', ').presence)
      end

      def log(workflow, trigger, **payload)
        logger.info(structured_payload(
          Labkit::Fields::DUO_WORKFLOW_ID => workflow.id, flow_trigger_id: trigger.id,
          service_account_id: workflow.service_account_id, Labkit::Fields::GL_USER_ID => workflow.user_id, **payload
        ))
      end
    end
    # rubocop:enable Scalability/IdempotentWorker
  end
end
