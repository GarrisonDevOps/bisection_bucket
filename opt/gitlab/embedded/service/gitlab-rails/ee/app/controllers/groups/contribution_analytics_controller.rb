# frozen_string_literal: true

class Groups::ContributionAnalyticsController < Groups::ApplicationController
  include ProductAnalyticsTracking

  before_action :authorize_read_contribution_analytics!
  before_action :redirect_to_new_dashboard, only: :show, if: -> {
    Feature.enabled?(:contributions_analytics_dashboard, group)
  }
  before_action :validate_start_date, only: :show, if: -> { request.format.json? }

  layout 'group'

  track_event :show,
    name: 'g_analytics_contribution',
    action: 'perform_analytics_usage_action',
    label: 'redis_hll_counters.analytics.analytics_total_unique_counts_monthly',
    destinations: %i[redis_hll snowplow]

  feature_category :value_stream_management
  urgency :low

  def show
    @start_date = data_collector.from
    @data_source_clickhouse = Gitlab::ClickHouse.enabled_for_contributions?(group)

    respond_to do |format|
      format.html
      format.json do
        render json: GroupAnalyticsSerializer
          .new(data_collector: data_collector)
          .represent(data_collector.users), status: :ok
      end
    end
  end

  private

  def start_date_param
    params.permit(:start_date)[:start_date]
  end

  def start_date
    @start_date_from_params ||= from_date(start_date_param)
  end

  def minimum_allowed_start_date
    Gitlab::ContributionAnalytics::DataCollector::MAX_RANGE_DAYS.days.ago.to_date
  end

  def data_collector
    @data_collector ||= Gitlab::ContributionAnalytics::DataCollector
      .new(group: @group, from: [start_date, minimum_allowed_start_date].max)
  end

  def validate_start_date
    return if start_date >= minimum_allowed_start_date

    message = format(
      s_('ContributionAnalytics|The given date range is larger than %{number_of_days} days'),
      number_of_days: Gitlab::ContributionAnalytics::DataCollector::MAX_RANGE_DAYS
    )

    render json: { message: message }, status: :unprocessable_entity
  end

  def authorize_read_contribution_analytics!
    render_404 unless group_has_access_to_feature? && user_has_access_to_feature?
  end

  def show_promotions?
    LicenseHelper.show_promotions?(current_user)
  end

  def group_has_access_to_feature?
    @group.licensed_feature_available?(:contribution_analytics)
  end

  def user_has_access_to_feature?
    can?(current_user, :read_group_contribution_analytics, @group)
  end

  def from_date(value)
    Date.parse(value)
  rescue Date::Error, TypeError
    1.week.ago.to_date
  end

  def tracking_namespace_source
    @group
  end

  def tracking_project_source
    nil
  end

  def redirect_to_new_dashboard
    redirect_to group_analytics_dashboards_path(group, vueroute: 'contributions_dashboard')
  end
end
