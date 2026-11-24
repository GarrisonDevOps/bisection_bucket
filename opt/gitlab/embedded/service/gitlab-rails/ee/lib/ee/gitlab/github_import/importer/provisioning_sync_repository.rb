# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Importer
        # Resolves the sync repository the initial import writes ExternalObject mappings for.
        module ProvisioningSyncRepository
          include ::Gitlab::Utils::StrongMemoize

          private

          def provisioning_sync_repository
            return unless ::Gitlab::GithubImport::Settings.new(project).enabled?(:continuous_sync)

            repository = project.import_sync_repository
            repository if repository&.provisioning?
          end
          strong_memoize_attr :provisioning_sync_repository
        end
      end
    end
  end
end
