# frozen_string_literal: true

module EE
  module Resolvers
    module Analytics
      module CycleAnalytics
        module DeploymentCountResolver
          extend ::Gitlab::Utils::Override

          private

          override :count
          def count(args)
            # Only licensed customers can get the aggregated DORA data (premium, ultimate)
            return super unless ::Gitlab::Analytics::CycleAnalytics.licensed?(object)

            if clickhouse_enabled?
              count_from_clickhouse(args)
            else
              count_from_postgres(args)
            end
          end

          def clickhouse_enabled?
            ::Gitlab::ClickHouse.enabled_for_analytics? &&
              ::Feature.enabled?(:dora_metrics_use_clickhouse, object)
          end

          def count_from_clickhouse(args)
            ::Analytics::CycleAnalytics::ClickHouse::DeploymentCountService.new(
              traversal_path: namespace_traversal_path,
              from: args[:from].to_date,
              to: args[:to].to_date
            ).execute
          end

          def count_from_postgres(args)
            projects_query = object.is_a?(Group) ? object.all_projects : object.project
            projects_query = projects_query.id_in(args[:project_ids]) if args[:project_ids]

            environments = ::Environment.for_project(projects_query).for_tier(:production)

            ::Dora::DailyMetrics
              .for_environments(environments)
              .in_range_of(args[:from].to_date, args[:to].to_date)
              .sum(:deployment_frequency)
          end

          def namespace_traversal_path
            if object.is_a?(Group)
              object.traversal_path(with_organization: true)
            else
              object.project.project_namespace.traversal_path(with_organization: true)
            end
          end
        end
      end
    end
  end
end
