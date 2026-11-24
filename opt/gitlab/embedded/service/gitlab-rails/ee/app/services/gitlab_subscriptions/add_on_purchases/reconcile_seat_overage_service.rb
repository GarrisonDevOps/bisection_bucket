# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class ReconcileSeatOverageService
      BATCH_SIZE = 50

      def initialize(add_on_purchase:)
        @add_on_purchase = add_on_purchase
      end

      def execute
        removed_seats_count = 0
        overage_count = assigned_user_ids_recent_first.count - add_on_purchase.quantity

        return ServiceResponse.success(payload: { removed_seats_count: removed_seats_count }) unless overage_count > 0

        user_ids_by_last_code_suggestion_usage =
          fetch_user_ids_by_last_code_suggestion_usage(assigned_user_ids_recent_first)

        # We are basically arranging the user_ids by priority to delete:
        # 1. User ids that haven't used any code suggestions with recently assigned first
        # 2. User ids that have used code suggestion with oldest usage first
        # 3. Get the first N users to delete, where N is the overage count
        user_ids_with_delete_priority = assigned_user_ids_recent_first - user_ids_by_last_code_suggestion_usage +
          user_ids_by_last_code_suggestion_usage
        user_ids_to_delete = user_ids_with_delete_priority.first(overage_count)

        user_ids_to_delete.each_slice(BATCH_SIZE) do |user_ids|
          deletable_assigned_users = add_on_purchase.assigned_users.by_user(user_ids)
          count = deletable_assigned_users.count
          removed_seats_count += count

          log_reconcile_user_add_on_assignments_deletion(user_ids)

          # rubocop:disable Cop/DestroyAll -- callbacks required
          deletable_assigned_users.destroy_all
          # rubocop:enable Cop/DestroyAll

          cache_keys = user_ids.map do |user_id|
            ::Ai::UserAuthorizer.duo_pro_cache_key_formatted(user_id)
          end

          Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
            Rails.cache.delete_multi(cache_keys)
          end
        end

        log_event(removed_seats_count) if removed_seats_count > 0

        ServiceResponse.success(payload: { removed_seats_count: removed_seats_count })
      end

      private

      attr_reader :add_on_purchase

      def assigned_user_ids_recent_first
        @assigned_user_ids_recent_first ||= add_on_purchase.assigned_users.order_by_id_desc.pluck_user_ids
      end

      def fetch_user_ids_by_last_code_suggestion_usage(user_ids)
        last_code_suggestion_usage_data(user_ids).sort_by { |_user_id, last_usage_date| last_usage_date }.map(&:first)
      end

      def last_code_suggestion_usage_data(user_ids)
        @last_code_suggestion_usage_data ||= Analytics::AiAnalytics::LastCodeSuggestionUsageService.new(
          nil, # no current user as it is maintenance job
          user_ids: user_ids,
          from: add_on_purchase.created_at,
          to: Time.zone.now
        ).execute.then(&:payload)
      end

      def log_reconcile_user_add_on_assignments_deletion(user_ids)
        Gitlab::AppLogger.info(
          message: 'ReconcileSeatOverageService destroyed UserAddOnAssignments',
          user_ids: user_ids.to_a,
          add_on: add_on_purchase.add_on.name,
          add_on_purchase: add_on_purchase.id,
          namespace: add_on_purchase.namespace&.path
        )
      end

      def log_event(deleted_count)
        Gitlab::AppLogger.info(
          message: 'ReconcileSeatOverageService removed AddOnPurchase seat overage',
          deleted_overage_count: deleted_count,
          add_on: add_on_purchase.add_on.name,
          add_on_purchase: add_on_purchase.id
        )
      end
    end
  end
end
