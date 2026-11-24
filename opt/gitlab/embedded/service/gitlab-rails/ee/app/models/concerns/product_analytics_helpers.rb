# frozen_string_literal: true

module ProductAnalyticsHelpers
  extend ActiveSupport::Concern

  def self.ai_impact_dashboard_globally_available?
    Gitlab::ClickHouse.globally_enabled_for_analytics?
  end

  def product_analytics_enabled?
    return false unless ::Gitlab::CurrentSettings.product_analytics_enabled?

    return false unless is_a?(Project)
    return false unless ::Feature.enabled?(:product_analytics_features, self)
    return false unless licensed_feature_available?(:product_analytics)

    root_group = group&.root_ancestor
    return false unless root_group.present?

    true
  end

  def value_streams_dashboard_available?
    licensed_feature =
      if is_a?(Project)
        :project_level_analytics_dashboard
      else
        :group_level_analytics_dashboard
      end

    licensed_feature_available?(licensed_feature)
  end

  def ai_impact_dashboard_available_for?(user)
    return false unless ProductAnalyticsHelpers.ai_impact_dashboard_globally_available?

    Ability.allowed?(user, :read_enterprise_ai_analytics, self)
  end

  def dora_metrics_dashboard_enabled?(user)
    Ability.allowed?(user, :read_dora4_analytics, self)
  end

  def contributions_dashboard_available?
    is_a?(Group) && Feature.enabled?(:contributions_analytics_dashboard, self)
  end

  def merge_request_analytics_enabled?(user)
    is_a?(Project) &&
      Ability.allowed?(user, :read_project_merge_request_analytics, self)
  end

  def product_analytics_dashboards(user)
    ::Analytics::Dashboards::Dashboard.for(container: self, user: user)
  end

  def product_analytics_dashboard(slug, user)
    ::Analytics::Dashboards::Dashboard.find_by_slug(container: self, user: user, slug: slug)
  end

  def default_dashboards_configuration_source
    is_a?(Project) ? self : nil
  end
end
