# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Stage
        module FinishImportWorker
          extend ::Gitlab::Utils::Override

          override :import
          def import(client, project)
            super

            enqueue_first_reconcile(project)
          end

          private

          # The first pass must not race the placeholder reference drain, so it waits for the import to finish.
          def enqueue_first_reconcile(project)
            return unless project.import_finished?

            repository = project.import_sync_repository
            return unless repository&.provider_canonical?

            generation = repository.application_generation
            ::Import::Sync::Repositories::ReconcileWorker.perform_async(repository.id, generation)
          end
        end
      end
    end
  end
end
