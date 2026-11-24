# frozen_string_literal: true

module EE
  module Gitlab
    module JiraImport
      extend ActiveSupport::Concern

      class_methods do
        extend ::Gitlab::Utils::Override

        override :validate_project_settings!
        def validate_project_settings!(project, user: nil, configuration_check: true)
          super

          return unless ::Import::Sync::Projects::WritePolicy.repository_mirroring_blocked?(project)

          raise ::Projects::ImportService::Error,
            _('Cannot import because updates from GitHub are on for this project.')
        end
      end
    end
  end
end
