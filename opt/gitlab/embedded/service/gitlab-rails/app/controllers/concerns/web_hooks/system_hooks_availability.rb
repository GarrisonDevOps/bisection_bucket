# frozen_string_literal: true

module WebHooks
  # System hooks are not offered on GitLab.com.
  # See https://gitlab.com/gitlab-org/gitlab/-/work_items/632603

  module SystemHooksAvailability
    extend ActiveSupport::Concern

    included do
      before_action :ensure_system_hooks_available!
    end

    private

    def ensure_system_hooks_available!
      render_404 unless system_hooks_available?
    end

    def system_hooks_available?
      !Gitlab.com? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- Not related to SaaS offerings
    end
  end
end
