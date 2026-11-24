# frozen_string_literal: true

module Analytics
  module AiAnalytics
    class LastCodeSuggestionUsageService
      MAX_USER_IDS_SIZE = 10_000
      private_constant :MAX_USER_IDS_SIZE

      def initialize(current_user, user_ids:, from:, to:)
        @current_user = current_user
        @user_ids = user_ids
        @from = from
        @to = to
      end

      # Return payload is a hash of {user_id => last_usage_date}
      def execute
        return feature_unavailable_error unless Gitlab::ClickHouse.globally_enabled_for_analytics?

        ServiceResponse.success(payload: last_usages)
      end

      private

      attr_reader :current_user, :user_ids, :from, :to

      def feature_unavailable_error
        ServiceResponse.error(
          message: s_('AiAnalytics|the ClickHouse data store is not available')
        )
      end

      def last_usages
        data = []

        user_ids.each_slice(MAX_USER_IDS_SIZE).map do |user_ids_slice|
          data += ClickHouse::Client.select(last_usages_query(user_ids_slice), :main)
        end

        data.to_h do |row|
          [row['user_id'], row['last_used_at']]
        end
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Not ActiveRecord but Clickhouse query builder
      def last_usages_query(user_ids)
        builder = ClickHouse::Client::QueryBuilder.new('code_suggestion_events_daily')

        builder.select(builder[:date].maximum.as('last_used_at'), builder[:user_id])
          .where(builder[:user_id].in(user_ids))
          .where(builder[:date].between(from.to_date..to.to_date))
          .group(:user_id)
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end
  end
end
