# frozen_string_literal: true

# Worker for updating any project specific caches.
class ProjectCacheWorker
  include ApplicationWorker

  data_consistency :always

  sidekiq_options retry: 3

  LEASE_TIMEOUT = 15.minutes.to_i
  # Slack for TTL rounding and clock skew
  TRAILING_UPDATE_MARGIN = 5.seconds.to_i

  feature_category :source_code_management
  urgency :high
  loggable_arguments 1, 2, 3
  idempotent!

  # project_id - The ID of the project for which to flush the cache.
  # files - An Array containing extra types of files to refresh such as
  #         `:readme` to flush the README and `:changelog` to flush the
  #         CHANGELOG.
  # statistics - An Array containing columns from ProjectStatistics to
  #              refresh, if empty all columns will be refreshed
  # refresh_statistics - A boolean that determines whether project statistics should
  #                     be updated.
  def perform(project_id, files = [], statistics = [], refresh_statistics = true)
    project = Project.find_by_id(project_id)

    return unless project

    skip_writes_if_replica(project) do
      update_statistics(project, statistics) if refresh_statistics
    end

    return unless project.repository.exists?

    project.repository.refresh_method_caches(files.map(&:to_sym))

    skip_writes_if_replica(project) do
      project.cleanup
    end
  end

  # NOTE: refreshes now if the lease is free. Either way, schedules one refresh
  # for when the lease expires, so events during the lease are not dropped.
  def update_statistics(project, statistics = [])
    return if Gitlab::Database.read_only?

    unless Feature.enabled?(:project_statistics_trailing_refresh, project)
      return update_statistics_without_trailing_refresh(project, statistics)
    end

    if try_obtain_lease_for(project.id, statistics)
      Projects::UpdateStatisticsService.new(project, nil, statistics: statistics).execute
    end

    schedule_trailing_update(project.id, statistics)
  end

  private

  # Remove with project_statistics_trailing_refresh, https://gitlab.com/gitlab-org/gitlab/-/work_items/633864
  def update_statistics_without_trailing_refresh(project, statistics)
    return unless try_obtain_lease_for(project.id, statistics)

    Projects::UpdateStatisticsService.new(project, nil, statistics: statistics).execute

    lease_key = project_cache_worker_key(project.id, statistics)
    UpdateProjectStatisticsWorker.perform_in(LEASE_TIMEOUT, lease_key, project.id, statistics)
  end

  def schedule_trailing_update(project_id, statistics)
    lease_key = project_cache_worker_key(project_id, statistics)
    lease_ttl = Gitlab::ExclusiveLease.new(lease_key, timeout: LEASE_TIMEOUT).ttl.to_i

    # One job per lease period. `- 2` keeps this key from outliving the lease,
    # despite TTL rounding and delay before the SET. Unguarded near expiry.
    if lease_ttl > 2
      trailing_lease = Gitlab::ExclusiveLease.new("#{lease_key}:trailing", timeout: lease_ttl - 2)
      return unless trailing_lease.try_obtain
    end

    UpdateProjectStatisticsWorker.perform_in(lease_ttl + TRAILING_UPDATE_MARGIN, lease_key, project_id, statistics)
  end

  def try_obtain_lease_for(project_id, statistics)
    Gitlab::ExclusiveLease
      .new(project_cache_worker_key(project_id, statistics), timeout: LEASE_TIMEOUT)
      .try_obtain
  end

  def project_cache_worker_key(project_id, statistics)
    ["project_cache_worker", project_id, *statistics.sort].join(":")
  end
end

ProjectCacheWorker.prepend_mod_with('ProjectCacheWorker')
