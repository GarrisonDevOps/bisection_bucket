# frozen_string_literal: true

module Groups
  class HookLogsController < Groups::ApplicationController
    include ::WebHooks::HookLogActions

    layout 'group_settings'

    private

    def hook
      @hook ||= @group.hooks.find(hook_id_param)
    end

    def hook_id_param
      params.permit(:hook_id)[:hook_id]
    end

    def after_retry_redirect_path
      edit_group_hook_path(@group, hook)
    end

    def hook_log_container
      group
    end
  end
end
