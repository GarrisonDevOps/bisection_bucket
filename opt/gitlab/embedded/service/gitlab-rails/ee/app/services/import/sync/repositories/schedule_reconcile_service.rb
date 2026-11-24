# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Marks one or more data domains of a repository as needing reconciliation by advancing their desired
      # generation. It only writes the domain rows; it never calls the provider or enqueues a job.
      class ScheduleReconcileService
        def initialize(repository, domains:, event_at: nil)
          @repository = repository
          @domains = Array(domains).map(&:to_s).uniq
          @event_at = event_at
        end

        # Raises ArgumentError for an unknown domain and Errors::InactiveAuthorityError when GitHub is not the
        # active authority; neither writes anything.
        def execute
          validate_domains!

          repository.with_lock do
            validate_authority!
            application_generation = repository.application_generation
            states = locked_states

            desired_generations = domains.to_h do |domain|
              state = states.fetch(domain)
              state.desired_generation += 1
              state.state = :pending unless state.running? || state.paused? || state.disconnected?
              state.last_event_at = [state.last_event_at, event_at].compact.max
              state.save!

              [domain, state.desired_generation]
            end

            ServiceResponse.success(
              payload: { application_generation: application_generation, desired_generations: desired_generations }
            )
          end
        end

        private

        attr_reader :repository, :domains, :event_at

        def validate_domains!
          unknown_domains = domains - Import::Sync::RepositoryState.domains.keys
          return if unknown_domains.empty?

          raise ArgumentError, "Unknown import sync domain: #{unknown_domains.first}"
        end

        def validate_authority!
          return if repository.provisioning? || repository.provider_canonical?

          raise Errors::InactiveAuthorityError, 'GitHub updates are no longer active for this project'
        end

        def locked_states
          repository.sync_states_for_update(domains)
        end
      end
    end
  end
end
