# frozen_string_literal: true

module Geo
  # Marks container repositories verified on the primary at or after a given
  # timestamp as verification_pending, so that Geo periodic verification
  # workers re-checksum them and secondaries detect and resync any changes.
  #
  # Neither filter has index coverage suitable for batch boundary queries
  # (`verified_at` is rewritten on every successful checksum, and the
  # `verification_state` index cannot serve a `!=` predicate ordered by primary
  # key), so this iterates the bare table in primary-key batches and applies
  # both filters within each PK-bounded batch, where they are cheap
  # ("slow iteration", see
  # https://docs.gitlab.com/development/database/iterating_tables_in_batches/#slow-iteration).
  #
  # Re-running after an interruption is safe and resumes naturally: rows
  # already updated became verification_pending and fall out of the scope.
  class ReverifyContainerRepositoriesService
    BATCH_SIZE = 1_000

    def initialize(verified_after:)
      @verified_after = verified_after
    end

    def execute
      updated = 0

      each_filtered_batch { |relation| updated += relation.update_all(verification_state: pending_value) }

      ServiceResponse.success(
        message: "Marked #{updated} container repositories for reverification.",
        payload: { count: updated }
      )
    end

    # Counts the records `execute` would update, without updating anything.
    def dry_run
      count = 0

      each_filtered_batch { |relation| count += relation.count }

      ServiceResponse.success(
        message: "DRY RUN: #{count} container repositories would be marked for reverification.",
        payload: { count: count }
      )
    end

    private

    attr_reader :verified_after

    def each_filtered_batch
      Geo::ContainerRepositoryState.each_batch(of: BATCH_SIZE) do |relation|
        yield relation.verification_state_not_pending.verified_after(verified_after)
      end
    end

    def pending_value
      Geo::VerificationState::VERIFICATION_STATE_VALUES[:verification_pending]
    end
  end
end
