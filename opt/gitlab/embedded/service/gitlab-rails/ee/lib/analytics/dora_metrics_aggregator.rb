# frozen_string_literal: true

module Analytics
  module DoraMetricsAggregator
    class << self
      SIPHON_TABLES = %i[environments dora_daily_metrics].freeze

      # Pass use_click_house: when the caller already decided, so the checks don't run twice.
      def aggregate_for(use_click_house: nil, **params)
        use_click_house = use_click_house?(**params) if use_click_house.nil?

        data = aggregate_from_click_house(params) if use_click_house

        data ||= aggregate_from_postgres(params)

        post_process_deployment_frequency!(data, params)
      end

      # Only callers that pass the container opt in; the performance score calculator stays on PostgreSQL.
      def use_click_house?(container: nil, **)
        return false unless container
        return false unless ::Gitlab::ClickHouse.enabled_for_analytics?(container)
        return false unless ::Feature.enabled?(:dora_metrics_clickhouse_aggregation, container.root_ancestor)

        SIPHON_TABLES.all? { |table| ::Gitlab::ClickHouse.siphon_enabled?(table) }
      end

      private

      # Returns nil on a ClickHouse error so the caller falls back to PostgreSQL. use_click_house? can't
      # catch an outage: siphon_enabled? caches a positive result for the life of the process.
      def aggregate_from_click_house(params)
        ClickHouseQuery.new(
          container: params[:container],
          project_ids: params[:project_ids],
          metrics: params[:metrics],
          interval: params[:interval],
          start_date: params[:start_date],
          end_date: params[:end_date],
          environment_tiers: params[:environment_tiers]
        ).execute
      rescue ::ClickHouse::Client::Error, *::Gitlab::HTTP::HTTP_ERRORS => e
        ::Gitlab::ErrorTracking.track_exception(e, container_type: params[:container].class.name,
          container_id: params[:container].id)
        nil
      end

      def aggregate_from_postgres(params)
        ::Dora::DailyMetrics
          .for_environments(::Environment.for_project(params[:projects]).for_tier(params[:environment_tiers]))
          .in_range_of(params[:start_date], params[:end_date])
          .aggregate_for!(params[:metrics], params[:interval])
      end

      # The deployment frequency DB query returns the number of deployments which is not
      # the actual deployment frequency. To get the deployment frequency, we post-process
      # the data and calculate the average deployments within the time range.
      def post_process_deployment_frequency!(data, params)
        df_metric_name = Dora::DeploymentFrequencyMetric::METRIC_NAME

        return data unless params[:metrics].include?(df_metric_name)

        interval_day_counts = case params[:interval]
                              when Dora::DailyMetrics::INTERVAL_ALL
                                # number of days between a date range (inclusive)
                                { nil => (params[:end_date] - params[:start_date]).to_i + 1 }
                              when Dora::DailyMetrics::INTERVAL_MONTHLY
                                # Calculating the number of days monthly by iterating over the days
                                # since date ranges can be arbitrary, for example:
                                # 2022-01-15 - 2022-02-28
                                #
                                # - For January, 2022-01-01: 17 days
                                # - For February, 2022-02-01: 28 days
                                (params[:start_date]..params[:end_date]).each_with_object({}) do |date, hash|
                                  beginning_of_month = date.beginning_of_month
                                  hash[beginning_of_month] ||= 0
                                  hash[beginning_of_month] += 1
                                end
                              end

        data.each do |row|
          next if interval_day_counts.nil?
          next if row[df_metric_name].nil?

          row['deployment_count'] = row[df_metric_name]
          row[df_metric_name] = row[df_metric_name].fdiv(interval_day_counts[row['date']])
        end

        data
      end
    end
  end
end
