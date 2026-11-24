# frozen_string_literal: true

module Analytics
  module AnalyticsDashboardsHelper
    def analytics_dashboards_list_app_data(namespace)
      is_project = project?(namespace)
      is_group = group?(namespace)

      {
        is_project: is_project.to_s,
        is_group: is_group.to_s,
        dashboard_empty_state_illustration_path: image_path('illustrations/empty-state/empty-dashboard-md.svg'),
        namespace_full_path: namespace.full_path,
        router_base: router_base(namespace),
        overview_counts_aggregation_enabled: overview_counts_aggregation_enabled?(namespace).to_s,
        has_scoped_labels_feature: has_scoped_labels_feature?(namespace).to_s,
        data_source_clickhouse: ::Gitlab::ClickHouse.enabled_for_contributions?(namespace).to_s,
        merge_request_throughput_data_source_clickhouse:
          merge_request_throughput_data_source_clickhouse?(namespace).to_s,
        explore_dashboards_path: explore_dashboards_promo_path
      }
    end

    private

    # Only set when the user can reach the Explore analytics dashboards space,
    # so the promo cannot link somewhere that renders a 404.
    def explore_dashboards_promo_path
      return unless ::Feature.enabled?(:explore_analytics_dashboards, current_user)

      explore_analytics_dashboards_path
    end

    def project?(namespace)
      namespace.is_a?(Project)
    end

    def group?(namespace)
      namespace.is_a?(Group)
    end

    # Siphon populates the ClickHouse merge_requests table on GitLab.com only.
    def merge_request_throughput_data_source_clickhouse?(namespace)
      ::Gitlab::ClickHouse.enabled_for_analytics?(namespace) &&
        ::Gitlab::Saas.feature_available?(:siphon_clickhouse_analytics)
    end

    def overview_counts_aggregation_enabled?(namespace)
      root_namespace = namespace.root_ancestor
      return true if root_namespace.value_stream_dashboard_aggregation&.enabled

      false
    end

    def router_base(namespace)
      return project_analytics_dashboards_path(namespace) if project?(namespace)

      group_analytics_dashboards_path(namespace)
    end

    def has_scoped_labels_feature?(namespace)
      namespace.licensed_feature_available?(:scoped_labels)
    end
  end
end
