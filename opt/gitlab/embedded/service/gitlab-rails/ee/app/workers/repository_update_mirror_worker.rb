# frozen_string_literal: true

class RepositoryUpdateMirrorWorker
  UpdateError = Class.new(StandardError)

  include ApplicationWorker

  idempotent!
  data_consistency :sticky
  worker_has_external_dependencies!
  include ProjectStartImport
  include Repositories::MirrorUpdateMetrics
  include Sidekiq::InterruptionsExhausted

  feature_category :source_code_management

  sidekiq_options retry: false, status_expiration: Gitlab::Import::StuckImportJob::IMPORT_JOBS_EXPIRATION

  sidekiq_interruptions_exhausted do |job|
    new.perform_failure(job['args'].first, job['jid'])
  end

  attr_accessor :project, :repository, :current_user

  def perform(project_id)
    project = Project
                .with_import_state
                .inc_routes
                .with_group
                .include_project_feature
                .find_by_id(project_id)

    return unless project

    if ::Import::Sync::Projects::WritePolicy.repository_mirroring_blocked?(project)
      # import_state is already `scheduled` by the time this job runs (see
      # EE::Project#add_import_job); leaving it there instead of failing it would hold
      # mirror capacity until it eventually times out as a misleading "Import timed out".
      fail_mirror(project, 'GitHub updates control repository mirroring')
      return
    end

    @current_user = project.mirror_user || project.creator

    return unless start_mirror(project)

    result = Projects::UpdateMirrorService.new(project, @current_user).execute
    raise UpdateError, result[:message] if result[:status] == :error

    finish_mirror(project) unless result[:async]
  rescue UpdateError => ex
    fail_mirror(project, ex.message)
    raise
  rescue StandardError, GRPC::Core::CallError => ex
    return unless project

    fail_mirror(project, ex.message)
    raise UpdateError, "#{ex.class}: #{ex.message}"
  end

  # Called by reliable fetch once the job has been interrupted too many times.
  # Without this the import state stays `started` until StuckImportJob sweeps it 24h later.
  # The jid check stops a late quarantine from failing a newer run of the same mirror.
  def perform_failure(project_id, jid)
    self.jid = jid

    project = Project.with_import_state.find_by_id(project_id)
    import_state = project&.import_state
    return unless import_state&.scheduled? || import_state&.started?
    return unless import_state.jid == jid

    fail_mirror(project, 'Mirror update reached the maximum number of interruptions')
  end

  private

  def start_mirror(project)
    import_state = project.import_state

    if start(import_state)
      Gitlab::AppLogger.info(message: "Mirror update for #{project.full_path} started. Waiting duration: #{import_state.mirror_waiting_duration}", jid: jid)
      metric_mirror_waiting_duration_seconds.observe({}, import_state.mirror_waiting_duration)

      true
    else
      Gitlab::AppLogger.info(message: "Project #{project.full_path} was in inconsistent state: #{import_state.status}.", jid: jid)
      false
    end
  end

  def fail_mirror(project, message)
    project.import_state.mark_as_failed(message)
    Gitlab::AppLogger.error(message: "Mirror update for #{project.full_path} failed with the following message: #{message}.", jid: jid)
  end

  def finish_mirror(project)
    project.import_state.finish
    log_mirror_update_finished(project)
  end

  def metric_mirror_waiting_duration_seconds
    @metric_mirror_waiting_duration_seconds ||= Gitlab::Metrics.histogram(
      :gitlab_repository_mirror_waiting_duration_seconds,
      'Waiting length for repository mirror',
      {},
      [1.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 2400.0, 3600.0]
    )
  end
end
