# frozen_string_literal: true

class UserProjectAccessChangedService
  DELAY = 1.hour

  HIGH_PRIORITY = :high
  MEDIUM_PRIORITY = :medium
  LOW_PRIORITY = :low
  # For changes that can only grant access, such as a new membership. Resolved per user: medium
  # when the user's project access is read from memberships, since only lists and search then
  # wait for the table, and high for everyone else.
  GRANT_PRIORITY = :grant

  SAFETY_NET_REFRESH_PURPOSE = 'safety_net'

  def initialize(user_ids)
    @user_ids = Array.wrap(user_ids)
  end

  def execute(priority: HIGH_PRIORITY)
    return if @user_ids.empty?

    if Authz::ProjectAuthorizations::RefreshEvent.replaces_sidekiq?(:memberships)
      leave_to_refresh_queue(priority)
      return
    end

    case priority
    when HIGH_PRIORITY
      execute_high_priority_refresh(@user_ids)
    when MEDIUM_PRIORITY
      execute_medium_priority_refresh(@user_ids)
    when LOW_PRIORITY
      execute_low_priority_refresh
    when GRANT_PRIORITY
      execute_grant_refresh
    end
  end

  private

  # Every change that calls this writes a row whose database trigger queues a refresh event. Users whose
  # access may have changed stay on the primary, so their next request reads that change.
  def leave_to_refresh_queue(priority)
    ::User.sticking.bulk_stick(:user, @user_ids) unless priority == LOW_PRIORITY
  end

  def execute_high_priority_refresh(user_ids)
    AuthorizedProjectsWorker.bulk_perform_async(bulk_args_for(user_ids)) # rubocop:disable Scalability/BulkPerformWithContext -- the user ID argument identifies each job
    ::User.sticking.bulk_stick(:user, user_ids)
  end

  def execute_medium_priority_refresh(user_ids)
    AuthorizedProjectUpdate::UserRefreshWithLowUrgencyWorker.bulk_perform_async(bulk_args_for(user_ids)) # rubocop:disable Scalability/BulkPerformWithContext -- the user ID argument identifies each job
  end

  def execute_grant_refresh
    deferrable_user_ids, immediate_user_ids = @user_ids.partition { |user_id| defer_grant_refresh?(user_id) }

    execute_high_priority_refresh(immediate_user_ids) if immediate_user_ids.any?
    return if deferrable_user_ids.empty?

    execute_medium_priority_refresh(deferrable_user_ids)
    # The membership was just written. Keep the user on the primary so their next request
    # resolves access from it rather than from a replica that has not caught up.
    ::User.sticking.bulk_stick(:user, deferrable_user_ids)
  end

  def defer_grant_refresh?(user_id)
    Authz::UserProjectGrants.resolves_from_memberships?(user_id)
  end

  def execute_low_priority_refresh
    return if Feature.enabled?(:do_not_run_safety_net_auth_refresh_jobs, :instance)

    # The actor is the user being refreshed, so each user is on exactly one path.
    db_queued_user_ids, legacy_user_ids = @user_ids.partition do |user_id|
      Feature.enabled?(:use_db_to_queue_safety_net_auth_refresh, ::User.actor_from_id(user_id))
    end

    # Legacy path first so a failure in the newer queue path cannot block it.
    enqueue_legacy_safety_net_jobs(legacy_user_ids) if legacy_user_ids.any?
    Authz::ProjectAuthorizationReverification.queue_users(db_queued_user_ids) if db_queued_user_ids.any?
  end

  def enqueue_legacy_safety_net_jobs(user_ids)
    Gitlab::ApplicationContext.with_raw_context(
      authorized_projects_refresh_purpose: SAFETY_NET_REFRESH_PURPOSE
    ) do
      # rubocop:disable Scalability/BulkPerformWithContext -- related_class context is set by the wrapping block
      with_related_class_context do
        AuthorizedProjectUpdate::UserRefreshFromReplicaWorker.bulk_perform_in(
          DELAY, bulk_args_for(user_ids), batch_size: 100, batch_delay: 30.seconds)
      end
      # rubocop:enable Scalability/BulkPerformWithContext
    end
  end

  def bulk_args_for(user_ids)
    user_ids.map { |id| [id] }
  end

  def with_related_class_context(&block)
    current_caller_id = Gitlab::ApplicationContext.current_context_attribute('meta.caller_id').presence
    Gitlab::ApplicationContext.with_context(related_class: current_caller_id, &block)
  end
end
