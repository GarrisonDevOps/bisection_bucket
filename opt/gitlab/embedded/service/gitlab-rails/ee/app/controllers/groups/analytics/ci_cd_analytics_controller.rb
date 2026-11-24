# frozen_string_literal: true

class Groups::Analytics::CiCdAnalyticsController < Groups::Analytics::ApplicationController
  include ProductAnalyticsTracking

  layout 'group'

  before_action -> { authorize_view_by_action!(:view_group_ci_cd_analytics) }

  before_action do
    push_licensed_feature(:group_ci_cd_analytics_releases, @group)
    push_licensed_feature(:group_ci_cd_analytics_pipelines, @group)

    push_frontend_feature_flag(:group_ci_cd_analytics_pipelines_ff, @group)
  end

  def show; end
end
