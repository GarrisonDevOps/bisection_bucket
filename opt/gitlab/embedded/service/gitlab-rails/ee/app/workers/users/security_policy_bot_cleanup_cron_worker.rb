# frozen_string_literal: true

module Users
  class SecurityPolicyBotCleanupCronWorker
    include ApplicationWorker
    include CronjobQueue

    idempotent!
    data_consistency :sticky
    feature_category :security_policy_management

    BATCH_SIZE = 100
    MAX_BATCHES = 10

    def perform
      options = { skip_authorization: true, hard_delete: false,
                  reason_for_deletion: "Security policy bot no longer associated with any project" }
      users_to_ignore = []

      MAX_BATCHES.times do
        users = fetch_orphaned_bots(users_to_ignore)

        break if users.blank?

        users.each do |user|
          admin_user = admin_bot_for_organization_id(user.organization_id)
          destroy_service = Users::DestroyService.new(admin_user)

          with_context(user: user) do
            destroy_service.execute(user, options)
          rescue Gitlab::Access::AccessDeniedError, Users::DestroyService::DestroyError => e
            users_to_ignore << user.id
            Gitlab::ErrorTracking.track_exception(e, user_id: user.id)
          end
        end
      end
    end

    private

    # Materializes the orphaned-bots query and returns the array of users.
    # If the query times out, logs the exception and returns nil so the
    # caller breaks out of the batch loop. The cron will retry on the next
    # scheduled run.
    # rubocop:disable Database/RescueQueryCanceled -- timeout is logged; the cron retries on the next run.
    def fetch_orphaned_bots(users_to_ignore)
      User.orphaned_security_policy_bots.where_not_in(users_to_ignore).limit(BATCH_SIZE).to_a
    rescue ActiveRecord::QueryCanceled => e
      Gitlab::ErrorTracking.log_exception(e, worker: self.class.name)
      nil
    end
    # rubocop:enable Database/RescueQueryCanceled

    def admin_bot_for_organization_id(organization_id)
      @admin_bots ||= {}
      @admin_bots[organization_id] ||= Users::Internal.in_organization(organization_id).admin_bot
    end
  end
end
