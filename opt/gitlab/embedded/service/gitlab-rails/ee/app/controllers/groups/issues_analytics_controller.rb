# frozen_string_literal: true

class Groups::IssuesAnalyticsController < Groups::ApplicationController
  include IssuableCollections
  include ProductAnalyticsTracking

  before_action :authorize_read_group!
  before_action :authorize_read_issue_analytics!

  track_event :show,
    name: 'g_analytics_issues',
    action: 'perform_analytics_usage_action',
    label: 'redis_hll_counters.analytics.analytics_total_unique_counts_monthly',
    destinations: %i[redis_hll snowplow]

  feature_category :devops_reports
  urgency :low

  def show
    respond_to do |format|
      format.html

      format.json do
        @chart_data = IssuablesAnalytics.new(
          issuables: issuables_collection,
          months_back: chart_params[:months_back],
          actor: group
        ).data

        render json: @chart_data
      end
    end
  end

  private

  def chart_params
    params.permit(:months_back)
  end

  def authorize_read_issue_analytics!
    render_404 unless group.licensed_feature_available?(:issues_analytics)
  end

  def authorize_read_group!
    render_404 unless can?(current_user, :read_group, group)
  end

  def finder_type
    IssuesFinder
  end

  def default_state
    'all'
  end

  def preload_for_collection
    nil
  end

  def tracking_namespace_source
    group
  end

  def tracking_project_source
    nil
  end
end
