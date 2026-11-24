# frozen_string_literal: true

module API
  module Dora
    class Metrics < ::API::Base
      feature_category :continuous_delivery
      urgency :low

      dora_metrics_tags = %w[dora_metrics]
      helpers do
        params :dora_metrics_params do
          requires :metric,
            type: String,
            values: ::Dora::DailyMetrics::AVAILABLE_METRICS,
            desc: 'The DORA metric to fetch.'

          optional :start_date,
            type: Date,
            desc: 'Start date of the date range. Defaults to 3 months ago.'

          optional :end_date,
            type: Date,
            desc: 'End date of the date range. Defaults to the current date.'

          optional :interval,
            type: String,
            values: ::Dora::DailyMetrics::AVAILABLE_INTERVALS,
            default: ::Dora::AggregateMetricsService::DEFAULT_INTERVAL,
            desc: 'The bucketing interval.'

          optional :environment_tiers,
            type: Array[String],
            values: ::Environment.tiers.keys,
            default: ::Dora::AggregateMetricsService::DEFAULT_ENVIRONMENT_TIERS,
            desc: 'The tiers of the environments.'
        end

        def fetch!(container)
          params = declared_params(include_missing: false)

          params[:metrics] = [params[:metric]] if params[:metric]

          result = ::Dora::AggregateMetricsService
            .new(container: container, current_user: current_user, params: params)
            .execute

          return render_api_error!(result[:message], result[:http_status]) unless result[:status] == :success

          present transform_data(result[:data])
        end

        def transform_data(data)
          params = declared_params(include_missing: false)
          metric = params[:metric]

          data.map { |row| { 'date' => row['date'], 'value' => row[metric] } }
        end
      end

      params do
        requires :id,
          types: [String, Integer],
          desc: 'ID or URL-encoded path of the project.'
      end
      resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        namespace ':id/dora/metrics' do
          desc 'Retrieve project-level DORA metrics' do
            detail 'Retrieves DORA metrics for a specified project.'
            success [
              {
                code: 200,
                message: 'successful operation',
                examples: {
                  successfull_response: [
                    { "date" => "2021-03-01", "value" => 3 },
                    { "date" => "2021-03-02", "value" => 6 },
                    { "date" => "2021-03-03", "value" => 0 },
                    { "date" => "2021-03-04", "value" => 0 },
                    { "date" => "2021-03-05", "value" => 0 },
                    { "date" => "2021-03-06", "value" => 0 },
                    { "date" => "2021-03-07", "value" => 0 },
                    { "date" => "2021-03-08", "value" => 4 }
                  ]
                }
              }
            ]
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' }
            ]
            is_array true
            tags dora_metrics_tags
          end
          params do
            use :dora_metrics_params
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :read_dora_metric, boundary_type: :project
          get do
            fetch!(user_project)
          end
        end
      end

      params do
        requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
      end
      resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        namespace ':id/dora/metrics' do
          desc 'Retrieve group-level DORA metrics' do
            detail 'Retrieves DORA metrics for a specified group.'
            success [
              {
                code: 200,
                message: 'successful operation',
                examples: {
                  successfull_response: [
                    { "date" => "2021-03-01", "value" => 3 },
                    { "date" => "2021-03-02", "value" => 6 },
                    { "date" => "2021-03-03", "value" => 0 },
                    { "date" => "2021-03-04", "value" => 0 },
                    { "date" => "2021-03-05", "value" => 0 },
                    { "date" => "2021-03-06", "value" => 0 },
                    { "date" => "2021-03-07", "value" => 0 },
                    { "date" => "2021-03-08", "value" => 4 }
                  ]
                }
              }
            ]
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' }
            ]
            is_array true
            tags dora_metrics_tags
          end
          params do
            use :dora_metrics_params
          end
          route_setting :tier, :ultimate
          route_setting :authorization, permissions: :read_dora_metric, boundary_type: :group
          get do
            fetch!(user_group)
          end
        end
      end
    end
  end
end
