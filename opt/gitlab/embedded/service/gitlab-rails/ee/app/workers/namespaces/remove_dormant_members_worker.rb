# frozen_string_literal: true

module Namespaces
  class RemoveDormantMembersWorker
    include ApplicationWorker
    include LimitedCapacity::Worker

    feature_category :seat_cost_management
    data_consistency :sticky
    urgency :low

    idempotent!

    MAX_RUNNING_JOBS = 6

    def perform_work
      return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      namespace = find_next_namespace
      return unless namespace

      remove_dormant_members(namespace)
    end

    def remaining_work_count(*_args)
      namespaces_requiring_dormant_member_removal(max_running_jobs + 1).count
    end

    def max_running_jobs
      MAX_RUNNING_JOBS
    end

    private

    # rubocop: disable CodeReuse/ActiveRecord -- LimitedCapacity worker
    def find_next_namespace
      NamespaceSetting.transaction do
        namespace_setting = namespaces_requiring_dormant_member_removal
          .preload(:namespace)
          .order_by_last_dormant_member_review_asc
          .lock('FOR UPDATE SKIP LOCKED')
          .first

        next unless namespace_setting

        # Update the last_dormant_member_review_at so the same namespace isn't picked up in parallel
        namespace_setting.update_column(:last_dormant_member_review_at, Time.current)

        namespace_setting.namespace
      end
    end
    # rubocop: enable CodeReuse/ActiveRecord

    def namespaces_requiring_dormant_member_removal(limit = 1)
      NamespaceSetting.requiring_dormant_member_review(limit)
    end

    def remove_dormant_members(namespace)
      dormant_period = namespace.namespace_settings.remove_dormant_members_period.days.ago
      admin_bot = admin_bot_for_organization_id(namespace.organization_id)
      dormant_count = 0

      ::GitlabSubscriptions::SeatAssignment.dormant_in_namespace(namespace, dormant_period).find_each do |assignment|
        if namespace.owner_ids.include?(assignment.user_id)
          log_skip_reason(namespace.id, assignment.user_id, :is_owner)
          next
        end

        user = assignment.user

        next log_skip_reason(namespace.id, user.id, :bot_user) if user.bot?

        next log_skip_reason(namespace.id, user.id, :deactivated_user) if user.deactivated?

        ::Gitlab::Auth::CurrentUserMode.optionally_run_in_admin_mode(admin_bot) do
          if user.enterprise_user_of_group?(namespace)
            ::Users::DeactivateEnterpriseService.new(admin_bot, group: namespace).execute(user)
          else
            ::Members::ScheduleDeletionService.new(
              namespace, assignment.user_id, admin_bot, reason: :dormant_member_removal
            ).execute
          end
        end

        dormant_count += 1
      end

      log_monitoring_data(namespace.id, dormant_count)
    end

    def log_monitoring_data(namespace_id, dormant_count)
      Gitlab::AppLogger.info(
        message: 'Processed dormant member removal',
        namespace_id: namespace_id,
        dormant_count: dormant_count
      )
    end

    def log_skip_reason(namespace_id, user_id, reason)
      Gitlab::AppLogger.info(
        message: 'User deactivation skipped',
        reason: reason.to_s,
        user_id: user_id,
        namespace_id: namespace_id
      )
      nil
    end

    def admin_bot_for_organization_id(organization_id)
      @admin_bots ||= {}
      @admin_bots[organization_id] ||= Users::Internal.in_organization(organization_id).admin_bot
    end
  end
end
