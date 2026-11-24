# frozen_string_literal: true

class AuthorizedProjectsWorker
  include ApplicationWorker
  include Sidekiq::InterruptionsExhausted
  include Authz::UserRefreshLock

  data_consistency :sticky

  worker_resource_boundary :cpu

  sidekiq_options retry: 3

  feature_category :permissions
  urgency :high
  weight 2

  deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true

  idempotent!

  defer_on_database_health_signal :gitlab_main_org, [], 1.minute,
    indicators: [Gitlab::Database::HealthStatus::Indicators::WalRate]

  sidekiq_retries_exhausted do |job, _exception|
    schedule_safety_net_refresh(job)
  end

  sidekiq_interruptions_exhausted do |job|
    schedule_safety_net_refresh(job)
  end

  def self.defer_on_database_health_signal?
    Feature.enabled?(:defer_primary_auth_refresh_on_wal_rate, :instance)
  end

  # A given-up job may have applied only part of its changes, and nothing else
  # recomputes this user. Scheduled through Redis rather than the DB-queued
  # safety net because the primary is usually what just failed the job.
  def self.schedule_safety_net_refresh(job)
    Gitlab::ApplicationContext.with_raw_context(
      Labkit::Fields::CORRELATION_ID => job['correlation_id'],
      authorized_projects_refresh_purpose: UserProjectAccessChangedService::SAFETY_NET_REFRESH_PURPOSE
    ) do
      Gitlab::ApplicationContext.with_context(related_class: job['class']) do
        AuthorizedProjectUpdate::UserRefreshFromReplicaWorker
          .perform_in(UserProjectAccessChangedService::DELAY, job['args'].first)
      end
    end
  end
  private_class_method :schedule_safety_net_refresh

  def perform(user_id)
    user = User.find_by_id(user_id)

    return unless user

    service = Users::RefreshAuthorizedProjectsService.new(user, source: self.class.name)

    with_user_refresh_lock(user) { service.execute }
  rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
    reschedule_on_lock_contention(user_id)
  end
end
