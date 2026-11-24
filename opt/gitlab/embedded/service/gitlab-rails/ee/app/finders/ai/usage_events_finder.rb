# frozen_string_literal: true

module Ai
  class UsageEventsFinder
    attr_reader :current_user, :namespace, :from, :to, :events, :users

    # rubocop: disable CodeReuse/Finder -- For being able to use Clickhouse Finder along with Postgres
    def initialize(current_user, **options)
      @current_user = current_user
      @options = options
      @namespace = options[:namespace]
    end

    def execute
      if ::Gitlab::ClickHouse.enabled_for_analytics?(@namespace)
        Ai::ClickHouseUsageEventsFinder.new(@current_user, **@options).execute
      else
        Ai::PostgresqlUsageEventsFinder.new(@current_user, **@options).execute
      end
    end
    # rubocop: enable CodeReuse/Finder
  end
end
