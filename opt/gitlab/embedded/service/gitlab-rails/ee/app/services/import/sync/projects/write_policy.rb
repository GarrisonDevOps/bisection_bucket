# frozen_string_literal: true

module Import
  module Sync
    module Projects
      class WritePolicy
        def self.read_only?(project)
          return false unless project&.github_import?
          return false unless ::Feature.enabled?(:github_continuous_import_enforcement, project, type: :ops)

          project.import_sync_repository&.read_only? || false
        end

        def self.repository_mirroring_blocked?(project)
          return false unless project
          return false unless ::Feature.enabled?(:github_continuous_import_enforcement, project, type: :ops)

          project.import_sync_repository&.provider_bound? || false
        end
      end
    end
  end
end
