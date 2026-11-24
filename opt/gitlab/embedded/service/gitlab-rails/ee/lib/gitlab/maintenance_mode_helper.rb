# frozen_string_literal: true

module Gitlab
  module MaintenanceModeHelper
    def self.maintenance_mode_message
      ActionController::Base.helpers.sanitize(::Gitlab::CurrentSettings.maintenance_mode_message) ||
        _('GitLab is undergoing maintenance')
    end
  end
end
