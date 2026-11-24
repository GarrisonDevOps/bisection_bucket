# frozen_string_literal: true

class Groups::Analytics::ApplicationController < Groups::ApplicationController
  include GracefulTimeoutHandling

  skip_cross_project_access_check :show
  before_action :authenticate_user!

  feature_category :value_stream_management
  urgency :low

  private

  def self.increment_usage_counter(counter_klass, counter, *args)
    before_action(*args) { counter_klass.count(counter) }
  end

  def authorize_view_by_action!(action)
    render_403 unless can?(current_user, action, group)
  end

  def check_feature_availability!(feature)
    render_403 unless group && group.licensed_feature_available?(feature)
  end

  def project_id_param
    params.permit(:project_id)[:project_id]
  end

  def load_project
    return unless group && project_id_param

    @project = find_routable!(group.all_projects, project_id_param, request.fullpath)
  end

  private_class_method :increment_usage_counter
end
