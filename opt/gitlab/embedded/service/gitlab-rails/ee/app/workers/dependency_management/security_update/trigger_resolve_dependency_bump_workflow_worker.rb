# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class TriggerResolveDependencyBumpWorkflowWorker
      include ApplicationWorker
      include Gitlab::EventStore::Subscriber
      include Gitlab::InternalEventsTracking

      WORKFLOW_DEFINITION = 'resolve_dependency_bump/experimental'
      MAX_ITERATIONS = 2

      feature_category :dependency_management
      data_consistency :sticky
      urgency :throttled
      idempotent!
      concurrency_limit -> { 100 }

      def handle_event(event)
        pipeline_id = event.data[:pipeline_id]
        pipeline = ::Ci::Pipeline.find_by_id(pipeline_id)
        return unless pipeline

        merge_request = pipeline.all_merge_requests.opened.authored_by_dependency_bump_service_account.first
        return unless merge_request

        project = merge_request.project
        return unless project.duo_dependency_bump_breaking_changes_available?

        workflows = workflows_for(merge_request).to_a
        return if skip_due_to_workflow_state?(workflows)

        user = resolve_workflow_user(project)
        unless user
          disable_breaking_changes_setting(project)
          log_enabler_missing(merge_request, project)
          return
        end

        unless enabler_authorized?(user, project)
          disable_breaking_changes_setting(project)
          log_enabler_unauthorized(merge_request, project, user)
          return
        end

        consumer = find_consumer(user, project)
        unless consumer
          log_consumer_not_found(merge_request, project)
          return
        end

        # This run's iteration = existing workflows + the one we're about to
        # trigger. Read before the trigger to avoid depending on
        # read-after-write visibility.
        iteration = workflows.size + 1
        result = trigger_workflow(pipeline, merge_request, user, consumer)

        if result.success?
          track_workflow_triggered(merge_request, project, iteration)
        else
          handle_error(result, merge_request, project)
        end
      rescue StandardError => error
        log_and_raise_exception(error, pipeline_id)
      end

      private

      def skip_due_to_workflow_state?(workflows)
        workflows.size >= MAX_ITERATIONS || workflows.any? { |workflow| workflow.status_group == :active }
      end

      def workflows_for(merge_request)
        ::Ai::DuoWorkflows::Workflow
          .for_merge_request(merge_request)
          .with_workflow_definition(WORKFLOW_DEFINITION)
      end

      def resolve_workflow_user(project)
        project.project_setting.duo_dependency_bump_breaking_changes_enabled_by
      end

      def enabler_authorized?(user, project)
        Ability.allowed?(user, :duo_workflow, project)
      end

      # Fail closed: if we can't run the flow as the user who enabled the setting,
      # turn the setting off so it stops re-triggering on every failed pipeline.
      def disable_breaking_changes_setting(project)
        return unless project.duo_dependency_bump_breaking_changes_enabled

        project.project_setting.update!(
          duo_dependency_bump_breaking_changes_enabled: false,
          duo_dependency_bump_breaking_changes_enabled_by_id: nil
        )
      end

      def find_consumer(user, project)
        ::Ai::Catalog::ItemConsumersFinder.new(user, params: {
          project_id: project.id,
          item_type: ::Ai::Catalog::Item::FLOW_TYPE,
          foundational_flow_reference: WORKFLOW_DEFINITION,
          include_inherited: false
        }).execute.first
      end

      def find_service_account(consumer)
        if consumer.project.present?
          # Project-level consumer: the service account is configured on the
          # group-level (parent) consumer, so inherit it from there.
          consumer.parent_item_consumer&.service_account
        else
          # Group-level consumer: the service account is held directly on it.
          consumer.service_account
        end
      end

      def trigger_workflow(pipeline, merge_request, user, consumer)
        service_account = find_service_account(consumer)

        flow_params = {
          item_consumer: consumer,
          service_account: service_account,
          execute_workflow: true,
          event_type: 'sidekiq_worker',
          user_prompt: pipeline_url(pipeline),
          merge_request_id: merge_request.iid,
          source_branch: merge_request.source_branch,
          additional_context: additional_context(merge_request)
        }

        ::Ai::Catalog::Flows::ExecuteService.new(
          project: merge_request.project,
          current_user: user,
          params: flow_params
        ).execute
      end

      def additional_context(merge_request)
        [
          {
            "Category" => "merge_request",
            "Content" => ::Gitlab::Json.dump({ "url" => ::Gitlab::UrlBuilder.build(merge_request) })
          }
        ]
      end

      def pipeline_url(pipeline)
        ::Gitlab::Routing.url_helpers.project_pipeline_url(pipeline.project, pipeline)
      end

      def log_consumer_not_found(merge_request, project)
        ::Gitlab::AppLogger.info(
          message: 'No consumer found for resolve_dependency_bump flow, setting is not enabled for this project',
          merge_request_id: merge_request.id,
          project_id: project.id,
          workflow_definition: WORKFLOW_DEFINITION
        )
      end

      def log_enabler_missing(merge_request, project)
        ::Gitlab::AppLogger.error(
          message: 'Enabler for resolve_dependency_bump setting is missing, disabling the setting',
          merge_request_id: merge_request.id,
          project_id: project.id
        )
      end

      def log_enabler_unauthorized(merge_request, project, user)
        ::Gitlab::AppLogger.error(
          message: 'Enabler is not authorized to execute resolve_dependency_bump workflow, disabling the setting',
          merge_request_id: merge_request.id,
          project_id: project.id,
          user_id: user.id
        )
      end

      def track_workflow_triggered(merge_request, project, iteration)
        track_internal_event(
          'trigger_resolve_dependency_bump_workflow',
          project: project,
          additional_properties: {
            label: 'automatic',
            value: merge_request.id,
            property: iteration.to_s
          }
        )
      end

      def handle_error(result, merge_request, project)
        ::Gitlab::AppLogger.error(
          message: 'Failed to call resolve_dependency_bump workflow service',
          merge_request_id: merge_request.id,
          project_id: project.id,
          error_message: result.message,
          failure_reason: result.reason
        )
      end

      def log_and_raise_exception(error, pipeline_id)
        ::Gitlab::ErrorTracking.log_and_raise_exception(
          error,
          pipeline_id: pipeline_id
        )
      end
    end
  end
end
