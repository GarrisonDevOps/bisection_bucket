# frozen_string_literal: true

class Projects::Analytics::IssuesAnalyticsController < Projects::ApplicationController
  include IssuableCollections
  include ProductAnalyticsTracking

  before_action :authorize_read_issue_analytics!

  track_event :show,
    name: 'p_analytics_issues',
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
          months_back: months_back_param,
          actor: project
        ).data

        render json: @chart_data
      end
    end
  end

  private

  def months_back_param
    params.permit(:months_back)[:months_back]
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
    project.namespace
  end

  def tracking_project_source
    project
  end
end
