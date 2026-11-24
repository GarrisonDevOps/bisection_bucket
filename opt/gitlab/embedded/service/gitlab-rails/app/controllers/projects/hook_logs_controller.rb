# frozen_string_literal: true

class Projects::HookLogsController < Projects::ApplicationController
  include WebHooks::HookLogActions

  layout 'project_settings'

  private

  def hook
    @hook ||= @project.hooks.find(hook_id_param)
  end

  def hook_id_param
    params.permit(:hook_id)[:hook_id]
  end

  def after_retry_redirect_path
    edit_project_hook_path(@project, hook)
  end

  def hook_log_container
    project
  end
end
