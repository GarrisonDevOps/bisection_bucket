# frozen_string_literal: true

module Import
  module Sync
    # The GitHub updates status that repository settings embed and the GitHub updates endpoints return.
    class GithubUpdatesStatusPresenter
      def initialize(import_sync_repository)
        @import_sync_repository = import_sync_repository
      end

      def to_h
        # The stop and update services change the states through their own queries, so don't reuse loaded ones.
        import_sync_repository.association(:sync_states).reset
        sync_states = import_sync_repository.sync_states.to_a

        {
          state: import_sync_repository.authority_state,
          read_only: ::Import::Sync::Projects::WritePolicy.read_only?(import_sync_repository.project),
          # A stop only completes with every data type current unless it skipped the final pass, and nothing
          # requests more work once the project is gitlab_canonical.
          final_pass_incomplete: import_sync_repository.gitlab_canonical? && sync_states.any?(&:lagging?),
          data: sync_states.index_by(&:domain).transform_values do |sync_state|
            {
              state: sync_state.state,
              last_updated_at: sync_state.last_successful_sync_at,
              last_checked_at: sync_state.last_sync_started_at
            }
          end
        }
      end

      private

      attr_reader :import_sync_repository
    end
  end
end
