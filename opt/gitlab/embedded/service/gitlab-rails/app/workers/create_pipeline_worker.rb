# frozen_string_literal: true

class CreatePipelineWorker # rubocop:disable Scalability/IdempotentWorker
  include ApplicationWorker
  include PipelineQueue

  data_consistency :sticky

  sidekiq_options retry: 3

  # Only the push path of this worker is in the create_pipeline_from_commit SLI. The GraphQL
  # pipelineCreate mutation also enqueues it (source merge_request_event with mergeRequestIid,
  # else api/web), and those API creations are out of scope.
  EXPERIENCE_SOURCE = 'push'

  sidekiq_retries_exhausted do |job, exception|
    project_id, _user_id, ref, source, _execute_options, creation_params = job['args']

    if report_experience?(source)
      Ci::PipelineCreation::ExperienceReporter.report_error(
        source: source,
        started_at: creation_params.to_h.dig('pipeline_creation_request', 'started_at'),
        project_id: project_id
      )
    end

    creation_params = creation_params.to_h

    pipeline_creation_request = creation_params['pipeline_creation_request']
    if pipeline_creation_request
      ::Ci::PipelineCreation::Requests.failed(
        pipeline_creation_request, 'Cannot create a pipeline after multiple retries.'
      )

      project = Project.find_by_id(project_id)
      process_auto_merge_for_ref(project, ref, pipeline_creation_request) if project
    end

    new.perform_failure(project_id, ref, exception, creation_params)
  end

  queue_namespace :pipeline_creation
  feature_category :pipeline_composition
  urgency :high
  worker_resource_boundary :cpu
  loggable_arguments 2, 3, 4

  # 30% of the 35% default limit of a high-urgency worker caps one user at about 10% of the shard's threads.
  concurrency_limit_scope(:user, max_percentage: 0.3,
    enabled: -> { Feature.enabled?(:ci_pipeline_creation_concurrency_limit_scope, :instance) })

  # A job deferred by the concurrency limit can wait for hours, so its pipeline creation request is
  # kept for longer than usual, and for at least the usual expiry when the job is resumed.
  DEFERRED_REQUEST_TTL = 1.hour

  # Raised when pipeline creation fails due to a transient Gitaly read during a
  # read-after-write window: the ref pointer or the commit it points at is not yet
  # visible on the node serving the read. This can be a user error, but is also known
  # to happen transiently on Praefect-backed storage due to replication delay.
  # Retried via Sidekiq (retry: 3) so the pipeline self-heals once Gitaly is consistent.
  TransientGitalyReadError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)

  def self.report_experience?(source)
    source.to_s == EXPERIENCE_SOURCE
  end

  # A ref request that ends without a pipeline leaves nothing to re-run auto-merge: no pipeline
  # completes and no head pipeline is updated. Run it for the merge requests waiting on this push.
  def self.process_auto_merge_for_ref(project, ref, pipeline_creation_request)
    return unless pipeline_creation_request.present?
    return if ::Ci::PipelineCreation::Requests.project_request?(project, pipeline_creation_request)

    merge_request_ids = MergeRequest
      .from_project(project)
      .from_source_branches(Gitlab::Git.ref_name(ref))
      .with_auto_merge_enabled
      .pluck_primary_key
    return if merge_request_ids.empty?

    AutoMergeProcessWorker.perform_async({ 'merge_request_id' => merge_request_ids })
  end

  def self.on_concurrency_limit_deferred(args)
    ::Ci::PipelineCreation::Requests.keep_alive(pipeline_creation_request(args), ttl: DEFERRED_REQUEST_TTL)
  end

  def self.on_concurrency_limit_resumed(args)
    ::Ci::PipelineCreation::Requests.keep_alive(pipeline_creation_request(args))
  end

  def self.pipeline_creation_request(args)
    _project_id, _user_id, _ref, _source, _execute_options, creation_params = args
    creation_params.to_h['pipeline_creation_request']
  end
  private_class_method :pipeline_creation_request

  def perform(project_id, user_id, ref, source, execute_options = {}, creation_params = {})
    Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/464671')

    project = Project.find_by_id(project_id)
    return unless project

    user = User.find_by_id(user_id)
    return unless user

    execute_options = execute_options.deep_symbolize_keys
    creation_params = creation_params.symbolize_keys.merge(ref: ref)

    response = Ci::CreatePipelineService
      .new(project, user, **creation_params)
      .execute(source, **execute_options)

    if response.error?
      raise_transient_gitaly_read_error!(response, project, **creation_params)
      fail_ref_request(creation_params[:pipeline_creation_request], response.message)
    end

    unless response.payload.persisted?
      self.class.process_auto_merge_for_ref(project, ref, creation_params[:pipeline_creation_request])
    end

    if self.class.report_experience?(source)
      Ci::PipelineCreation::ExperienceReporter.report(
        pipeline: response.payload,
        source: source,
        started_at: creation_params.with_indifferent_access.dig(:pipeline_creation_request, :started_at)
      )
    end

    return unless response.error?

    log_pipeline_errors(response.message, project, **creation_params)
  end

  def perform_failure(project_id, ref, exception, creation_params = {})
    project = Project.find_by_id(project_id)
    return unless project

    creation_params = creation_params.symbolize_keys.merge(ref: ref)

    log_pipeline_errors(exception.message, project, **creation_params)
  end

  private

  def log_pipeline_errors(error_message, project, **creation_params)
    data = {
      class: self.class.name,
      correlation_id: Labkit::Correlation::CorrelationId.current_id.to_s,
      project_id: project.id,
      project_path: project.full_path,
      message: "Error creating pipeline",
      errors: error_message,
      pipeline_params: sanitized_pipeline_params(**creation_params)
    }

    Sidekiq.logger.warn(data)
  end

  def sanitized_pipeline_params(**creation_params)
    creation_params.except(:push_options, :pipeline_creation_request)
  end

  def raise_transient_gitaly_read_error!(response, project, **creation_params)
    raise_on_reference_not_found!(response, **creation_params)
    raise_on_commit_not_found!(response, project)
  end

  # Ci::CreatePipelineService leaves ref requests to this worker, so a job that is retried keeps its
  # request in progress. Project requests are already failed by the service.
  def fail_ref_request(request, error)
    return unless ::Ci::PipelineCreation::Requests.ref_request?(request)

    ::Ci::PipelineCreation::Requests.failed(request, error)
  end

  def raise_on_reference_not_found!(response, **creation_params)
    return unless response.message == Gitlab::Ci::Pipeline::Chain::Validate::Repository::REFERENCE_NOT_FOUND_MESSAGE
    return unless Gitlab::Git.blank_ref?(creation_params[:before].to_s)

    raise TransientGitalyReadError, Gitlab::Ci::Pipeline::Chain::Validate::Repository::REFERENCE_NOT_FOUND_MESSAGE
  end

  def raise_on_commit_not_found!(response, project)
    return unless Feature.enabled?(:ci_create_pipeline_worker_retry_on_commit_not_found, project)
    return unless response.message == Gitlab::Ci::Pipeline::Chain::Validate::Repository::COMMIT_NOT_FOUND_MESSAGE

    raise TransientGitalyReadError, Gitlab::Ci::Pipeline::Chain::Validate::Repository::COMMIT_NOT_FOUND_MESSAGE
  end
end
