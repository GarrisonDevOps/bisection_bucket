# frozen_string_literal: true

module EE
  module Projects
    module ApplicationController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :flash_update_warnings
      def flash_update_warnings(result)
        warnings = result[::Govern::PolicyEngine::SettingsChangeGate::WARNINGS_RESULT_KEY]
        return if warnings.blank?

        flash[:warning] = warnings.join('; ')
      end

      override :auth_proc
      def auth_proc
        if controller_name == "projects" && action_name == "restore"
          super
        else
          ->(project) { !project.self_deletion_in_progress_or_hidden? }
        end
      end
    end
  end
end
