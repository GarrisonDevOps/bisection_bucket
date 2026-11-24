# frozen_string_literal: true

# PostReceiveService class
#
# Used for scheduling related jobs after a push action has been performed
class PostReceiveService
  attr_reader :user, :repository, :project, :params

  def initialize(user, repository, project, params)
    @user = user
    @repository = repository
    @project = project
    @params = params
  end

  def execute
    response = Gitlab::InternalPostReceive::Response.new

    mr_options = push_options.get(:merge_request)

    response.reference_counter_decreased = Gitlab::ReferenceCounter.new(params[:gl_repository]).decrease

    update_rebuildable_ref_cache if repository

    # Create ref-based pipeline creation requests early to ensure
    # pipeline_creating_for_ref? returns true as soon as possible, to make the
    # CI mergeability check's race window as small as possible.
    pipeline_creation_requests = prepare_pipeline_creation_requests

    # The PostReceive worker will normally invalidate the cache. However, it
    # runs asynchronously. If push options require us to create a new merge
    # request synchronously, we can't rely on that, so invalidate the cache here
    repository&.expire_branches_cache if mr_options&.fetch(:create, false)

    schedule_post_receive_worker(pipeline_creation_requests: pipeline_creation_requests)

    if mr_options.present?
      message = process_mr_push_options(mr_options, params[:changes])
      response.add_alert_message(message)
    end

    response.add_alert_message(broadcast_message)
    response.add_merge_request_urls(merge_request_urls)

    add_user_repository_messages(response)

    response
  end

  def push_options
    @push_options ||= begin
      options = params[:push_options] || []
      options += [Gitlab::PushOptions::CI_SKIP] if !!params.dig(:gitaly_context, 'skip-ci')
      Gitlab::PushOptions.new(options)
    end
  end

  def process_mr_push_options(push_options, changes)
    Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/28494')
    return unless repository

    unless repository.repo_type.project?
      return push_options_warning('Push options are only supported for projects')
    end

    service = ::MergeRequests::PushOptionsHandlerService.new(
      project: project, current_user: user, changes: changes, push_options: push_options
    ).execute

    if service.errors.present?
      push_options_warning(service.errors.join("\n\n"))
    end
  end

  def push_options_warning(warning)
    options = Array.wrap(params[:push_options]).map { |p| "'#{p}'" }.join(' ')
    "WARNINGS:\nError encountered with push options #{options}: #{warning}"
  end

  def merge_request_urls
    return [] unless repository&.repo_type&.project?

    ::MergeRequests::GetUrlsService.new(project: project).execute(params[:changes])
  end

  private

  def prepare_pipeline_creation_requests
    return unless repository&.repo_type&.project?
    return unless Feature.enabled?(:track_ref_pipeline_creation, project)
    # Git::BranchHooksService creates no branch pipeline for a merge request's source branch under this
    # setting, so a request started here would stay open until it expires.
    return if project.ci_skip_branch_pipelines_for_mrs?

    changes = Gitlab::ChangesList.new(params[:changes])
    requests = {}
    # Git::ProcessRefChangesService counts every pushed ref towards this limit, in push order, and
    # creates no pipeline past it, so those refs need no request.
    limit = Gitlab::CurrentSettings.git_push_pipeline_limit

    changes.each_with_index do |change, index|
      break if limit > 0 && index >= limit
      next unless Gitlab::Git.branch_ref?(change[:ref])
      next if Gitlab::Git.blank_ref?(change[:newrev])

      ref = change[:ref]
      requests[ref] = Ci::PipelineCreation::Requests.start_for_ref(project, ref)
    end

    requests.presence
  rescue ::Redis::BaseError, ::RedisClient::Error => e
    # A Redis failure here must not stop the push from being processed.
    Gitlab::ErrorTracking.track_exception(e, project_id: project.id)
    requests.presence
  end

  def schedule_post_receive_worker(pipeline_creation_requests: nil)
    worker = Repositories::PostReceiveWorker
    worker_params = { 'gitaly_context' => params[:gitaly_context] }
    if pipeline_creation_requests
      worker_params['pipeline_creation_requests'] = pipeline_creation_requests.transform_keys(&:to_s)
    end

    worker.perform_async(params[:gl_repository], params[:identifier],
      params[:changes], push_options.as_json, worker_params)
  end

  def add_user_repository_messages(response)
    # Neither User nor Repository are guaranteed to be returned; an orphaned write deploy
    # key could be used
    return unless user && repository

    redirect_message = Gitlab::Checks::ContainerMoved.fetch_message(user, repository)
    project_created_message = Gitlab::Checks::ProjectCreated.fetch_message(user, repository)

    response.add_basic_message(redirect_message)
    response.add_basic_message(project_created_message)
  end

  def update_rebuildable_ref_cache
    return unless repository.repo_type.project?

    changes = Gitlab::GitPostReceive.new(
      repository.container,
      params[:identifier],
      params[:changes]
    ).changes

    Gitlab::Repositories::RefCacheUpdateService.new(repository, changes).execute
  rescue StandardError => e
    Gitlab::ErrorTracking.track_exception(e, project_id: repository.container.id)
  end

  def broadcast_message
    banner = nil
    user_access_level = if project && user
                          user.max_member_access_for_project(project.id)
                        end

    if project
      scoped_messages =
        System::BroadcastMessage.current_banner_messages(
          current_path: project.full_path,
          user_access_level: user_access_level
        ).select do |message|
          message.target_path.present? && message.matches_current_path(project.full_path) && message.show_in_cli?
        end

      banner = scoped_messages.last
    end

    banner ||= System::BroadcastMessage.current_show_in_cli_banner_messages(user_access_level: user_access_level).last

    banner&.message
  end
end

PostReceiveService.prepend_mod_with('PostReceiveService')
