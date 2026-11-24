# frozen_string_literal: true

class Projects::HooksController < Projects::ApplicationController
  include ::WebHooks::HookActions

  # Authorize
  before_action :authorize_read_hook!, only: :index
  before_action :authorize_create_hook!, only: :create
  before_action :authorize_update_hook!, only: [:edit, :update]
  before_action :authorize_delete_hook!, only: :destroy
  before_action :authorize_test_hook!, only: :test
  before_action -> { check_rate_limit!(:web_hook_test, scope: { project: @project, user: current_user }) }, only: :test
  before_action :set_hide_search_settings

  respond_to :html

  layout "project_settings"

  urgency :low, [:test]

  def test
    result = TestHooks::ProjectService.new(hook, current_user, trigger_param).execute

    set_hook_execution_notice(result)

    redirect_back_or_default(default: { action: :index })
  end

  private

  def set_hide_search_settings
    @hide_search_settings = true
  end

  def relation
    @project.hooks
  end

  def hook_container
    @project
  end

  def hook
    @hook ||= @project.hooks.find(id_param)
  end

  def id_param
    params.permit(:id)[:id]
  end

  def trigger_param
    params.permit(:trigger).fetch(:trigger, 'push_events')
  end

  def trigger_values
    ProjectHook.triggers.values
  end

  def authorize_read_hook!
    render_404 unless can?(current_user, :read_webhook, project)
  end

  def authorize_create_hook!
    render_404 unless can?(current_user, :create_webhook, project)
  end

  def authorize_update_hook!
    render_404 unless can?(current_user, :update_webhook, project)
  end

  def authorize_delete_hook!
    render_404 unless can?(current_user, :delete_webhook, project)
  end

  def authorize_test_hook!
    render_404 unless can?(current_user, :test_webhook, project)
  end
end
