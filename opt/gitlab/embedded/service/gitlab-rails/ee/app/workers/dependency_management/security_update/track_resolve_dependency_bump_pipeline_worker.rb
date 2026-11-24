# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Records the outcome of a pipeline that runs on a dependency-bump MR branch
    # after the resolve_dependency_bump flow has pushed a fix, so we can measure
    # how many generated pipelines pass vs. fail.
    #
    # Attribution: a workflow must already exist for the MR AND have been created
    # before the pipeline. That ordering excludes the original failing pipeline
    # (which predates any workflow and is what triggers the flow), and it is
    # robust to the trigger worker creating the workflow concurrently for that
    # same failure.
    class TrackResolveDependencyBumpPipelineWorker
      include Gitlab::EventStore::Subscriber
      include Gitlab::InternalEventsTracking

      WORKFLOW_DEFINITION = TriggerResolveDependencyBumpWorkflowWorker::WORKFLOW_DEFINITION
      BRANCH_PREFIX = "#{::DependencyManagement::SecurityUpdate::Request::BRANCH_PREFIX}/".freeze

      feature_category :dependency_management
      data_consistency :delayed
      urgency :low
      idempotent!
      concurrency_limit -> { 100 }
      defer_on_database_health_signal :gitlab_main_org, [:duo_workflows_workflows], 1.minute

      def handle_event(event)
        pipeline = find_pipeline(event)
        return unless pipeline
        return unless pipeline.source_ref&.start_with?(BRANCH_PREFIX)

        # Deliberately not scoped to opened merge requests: a passing pipeline is what
        # unblocks the merge, so filtering on state here would drop successes far more
        # often than failures and skew the pass rate this worker exists to measure.
        merge_request = pipeline.all_merge_requests_by_recency
                                .authored_by_dependency_bump_service_account
                                .first
        return unless merge_request

        project = merge_request.project
        return unless project.duo_dependency_bump_breaking_changes_available?

        workflow = generating_workflow(merge_request, pipeline)
        return unless workflow

        track_internal_event(
          'generate_resolve_dependency_bump_pipeline',
          project: project,
          additional_properties: {
            label: event.data[:status],
            value: merge_request.id,
            property: workflow.id.to_s,
            pipeline_id: pipeline.id
          }
        )
      end

      private

      # `p_ci_pipelines` is partitioned, so scope the lookup to prune to one partition.
      # `partition_id` is absent from events published before it was added to the payload.
      def find_pipeline(event)
        partition_id = event.data[:partition_id]
        scope = partition_id ? ::Ci::Pipeline.in_partition(partition_id) : ::Ci::Pipeline

        scope.find_by_id(event.data[:pipeline_id])
      end

      # The workflow that generated this pipeline: the latest resolve_dependency_bump
      # workflow for the MR that was created before the pipeline.
      def generating_workflow(merge_request, pipeline)
        workflows_for(merge_request)
          .created_before(pipeline.created_at)
          .ordered_by_id_desc
          .first
      end

      def workflows_for(merge_request)
        ::Ai::DuoWorkflows::Workflow
          .for_merge_request(merge_request)
          .with_workflow_definition(WORKFLOW_DEFINITION)
      end
    end
  end
end
