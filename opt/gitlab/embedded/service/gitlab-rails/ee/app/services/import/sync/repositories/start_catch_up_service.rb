# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Hands a successfully imported project from bootstrap to ongoing updates: flips the authority from
      # provisioning to provider_canonical. Safe to call again after the flip, which changes nothing. The
      # first reconcile is enqueued by the finish stage, once the import has finished.
      class StartCatchUpService
        def initialize(repository)
          @repository = repository
        end

        # Returns true when GitHub holds the authority afterwards. Canceled or already
        # cut-over projects remain untouched and return false.
        def execute
          ApplicationLease.new(repository.id).execute do |lease_context|
            lease_context.verify!
            repository.with_lock do
              next false unless repository.provisioning? || repository.provider_canonical?

              flip_to_provider_canonical if repository.provisioning?
              true
            end
          end
        end

        private

        attr_reader :repository

        def flip_to_provider_canonical
          repository.update!(authority_state: :provider_canonical)

          ::Gitlab::GithubImport::Logger.info(
            message: 'import sync repository authority changed',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => repository.project_id,
            from: 'provisioning',
            to: 'provider_canonical'
          )
        end
      end
    end
  end
end
