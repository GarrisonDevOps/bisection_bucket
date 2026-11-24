# frozen_string_literal: true

module Resolvers
  module Analytics
    module CycleAnalytics
      module Concerns
        module IssuableStageResolver
          extend ActiveSupport::Concern

          UNSUPPORTED_CLICKHOUSE_FILTER_KEYS = %i[
            assignee_username author_username milestone_title label_name not project_ids
          ].freeze

          def resolve(**args)
            params = process_params(args)

            if use_clickhouse?(params)
              metric_class = self.class::CLICKHOUSE_METRIC_CLASS
              params = params.merge(
                from: params[:from]&.to_time&.utc&.beginning_of_day,
                to: params[:to]&.to_time&.utc&.end_of_day
              )
            else
              metric_class = self.class::METRIC_CLASS
            end

            metric = metric_class.new(stage: stage, current_user: current_user, options: params)

            formatted_data(metric)
          end

          def authorized?(*)
            ::Gitlab::Analytics::CycleAnalytics.licensed?(namespace) && ::Gitlab::Analytics::CycleAnalytics.allowed?(
              current_user, namespace)
          end

          private

          included do
            alias_method :namespace, :object
          end

          def use_clickhouse?(params)
            return false unless clickhouse_metric_class
            return false if UNSUPPORTED_CLICKHOUSE_FILTER_KEYS.any? { |key| params[key].present? }
            return false if ::Feature.disabled?(:dora_metrics_use_clickhouse, namespace)

            ::Gitlab::ClickHouse.enabled_for_analytics?
          end

          def clickhouse_metric_class
            return unless self.class.const_defined?(:CLICKHOUSE_METRIC_CLASS)

            self.class::CLICKHOUSE_METRIC_CLASS
          end

          def stage
            ::Analytics::CycleAnalytics::Stage.new(namespace: namespace)
          end

          def process_params(params)
            params[:not] = normalize_params(params[:not].to_h) if params[:not]
            params = normalize_params(params)
            params[:projects] = params[:project_ids] if params[:project_ids]
            params[:use_aggregated_data_collector] = true

            params
          end

          def normalize_params(params)
            assignees_value = params.delete(:assignee_usernames)
            params[:assignee_username] = assignees_value if assignees_value.present?
            params[:label_name] = params.delete(:label_names) if params[:label_names]
            params
          end

          def formatted_data(metric)
            value = metric.raw_value
            { value: value, unit: n_('day', 'days', value), links: metric.links }
          end
        end
      end
    end
  end
end
