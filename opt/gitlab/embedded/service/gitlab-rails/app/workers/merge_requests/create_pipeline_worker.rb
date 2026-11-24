# frozen_string_literal: true

module MergeRequests
  class CreatePipelineWorker
    include ApplicationWorker
    include PipelineQueue
    include MergeRequests::PublishesPipelineCreationCompletedEvent

    PipelineCreationRetryError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)

    data_consistency :sticky

    sidekiq_options retry: 3
    sidekiq_retry_in do |_count|
      10
    end

    queue_namespace :pipeline_creation
    feature_category :pipeline_composition
    urgency :high
    worker_resource_boundary :cpu
    idempotent!

    # 30% of the 35% default limit of a high-urgency worker caps one user at about 10% of the shard's threads.
    concurrency_limit_scope(:user, max_percentage: 0.3,
      enabled: -> { Feature.enabled?(:ci_pipeline_creation_concurrency_limit_scope, :instance) })

    # A job deferred by the concurrency limit can wait for hours, so its pipeline creation request is
    # kept for longer than usual, and for at least the usual expiry when the job is resumed.
    DEFERRED_REQUEST_TTL = 1.hour

    sidekiq_retries_exhausted do |job, _exception|
      pipeline_creation_request = pipeline_creation_request(job['args'])
      next unless pipeline_creation_request

      Ci::PipelineCreation::ExperienceReporter.report_error(
        source: :merge_request_event,
        started_at: pipeline_creation_request['started_at'],
        project_id: job['args'][0]
      )

      error_message = 'Cannot create a pipeline for this merge request after multiple retries.'

      ::Ci::PipelineCreation::Requests.failed(pipeline_creation_request, error_message)

      merge_request = ::Ci::PipelineCreation::Requests.merge_request_from_key(pipeline_creation_request['key'])

      GraphqlTriggers.ci_pipeline_creation_requests_updated(merge_request) if merge_request
    end

    def self.on_concurrency_limit_deferred(args)
      ::Ci::PipelineCreation::Requests.keep_alive(pipeline_creation_request(args), ttl: DEFERRED_REQUEST_TTL)
    end

    def self.on_concurrency_limit_resumed(args)
      ::Ci::PipelineCreation::Requests.keep_alive(pipeline_creation_request(args))
    end

    def self.pipeline_creation_request(args)
      _project_id, _user_id, _merge_request_id, params = args
      params.to_h['pipeline_creation_request']
    end
    private_class_method :pipeline_creation_request

    def perform(project_id, user_id, merge_request_id, params = {})
      project = Project.find_by_id(project_id)
      return unless project

      user = User.find_by_id(user_id)
      return unless user

      merge_request = MergeRequest.find_by_id(merge_request_id)
      return unless merge_request

      allow_duplicate = params.with_indifferent_access[:allow_duplicate]
      pipeline_creation_request = params.with_indifferent_access[:pipeline_creation_request]
      push_options = params.with_indifferent_access[:push_options]
      gitaly_context = params.with_indifferent_access[:gitaly_context]
      defer_request_completion = params.with_indifferent_access[:defer_request_completion]
      checkout_sha = params.with_indifferent_access[:checkout_sha]

      result = MergeRequests::CreatePipelineService
        .new(
          project: project,
          current_user: user,
          params: {
            allow_duplicate: allow_duplicate,
            pipeline_creation_request: pipeline_creation_request,
            push_options: push_options,
            gitaly_context: gitaly_context,
            defer_request_completion: defer_request_completion,
            checkout_sha: checkout_sha
          }
        ).execute(merge_request)

      raise PipelineCreationRetryError, result.message if result&.error? && result.reason == :retriable_error

      merge_request.update_head_pipeline

      complete_pipeline_creation_request(result, pipeline_creation_request, merge_request) if defer_request_completion

      publish_pipeline_creation_completed_event(
        project: project,
        merge_request_id: merge_request.id,
        pipeline_id: result.payload&.id
      )

      after_perform(merge_request)

      Ci::PipelineCreation::ExperienceReporter.report(
        pipeline: result.payload,
        source: :merge_request_event,
        started_at: pipeline_creation_request&.dig(:started_at)
      )
    end

    private

    def complete_pipeline_creation_request(result, pipeline_creation_request, merge_request)
      if result.error?
        error_message = result.message
        ::Ci::PipelineCreation::Requests.failed(pipeline_creation_request, error_message)
      else
        ::Ci::PipelineCreation::Requests.succeeded(pipeline_creation_request, result.payload.id)
      end

      GraphqlTriggers.ci_pipeline_creation_requests_updated(merge_request)
    end

    def after_perform(merge_request); end
  end
end

MergeRequests::CreatePipelineWorker.prepend_mod
