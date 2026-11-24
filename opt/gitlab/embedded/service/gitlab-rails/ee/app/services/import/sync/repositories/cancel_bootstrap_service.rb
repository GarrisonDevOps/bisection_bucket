# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Moves a row that can no longer sync to bootstrap_canceled, under StartCatchUpService's lease and row
      # lock. A held lease means a catch-up owns the row; it raises, like any other failure, so the caller decides
      # whether to retry or track it.
      class CancelBootstrapService
        def initialize(repository, from: %w[provisioning])
          @repository = repository
          @from = from
        end

        # Returns the authority state the row was moved from, or nil when it was left alone.
        def execute
          return unless repository && from.include?(repository.authority_state)

          ApplicationLease.new(repository.id).execute do |lease_context|
            lease_context.verify!
            repository.with_lock do
              previous_state = repository.authority_state
              next unless from.include?(previous_state)

              repository.update!(
                authority_state: :bootstrap_canceled, disconnect_reason: nil, restore_authority_state: nil
              )
              previous_state
            end
          end
        end

        private

        attr_reader :repository, :from
      end
    end
  end
end
