# frozen_string_literal: true

module Ml
  # Deletes the runs of an experiment, and their metrics, params and metadata, in statements of bounded size.
  # It stops when it reaches max_rows or the runtime limit, and the result tells if runs remain.
  class DeleteExperimentRunsService
    BATCH_SIZE = 100
    BATCH_PAUSE = 0.01
    # Metadata rows sit about 2 per heap page, so a cold statement reads a page for every 2 rows.
    RUN_CHILDREN_SUB_BATCH_SIZES = {
      Ml::CandidateMetric => 10_000,
      Ml::CandidateParam => 10_000,
      Ml::CandidateMetadata => 1_000
    }.freeze

    attr_reader :deleted_rows

    def initialize(experiment, max_rows:, runtime_limiter:)
      @experiment = experiment
      @max_rows = max_rows
      @runtime_limiter = runtime_limiter
      @deleted_rows = 0
    end

    def execute
      ServiceResponse.success(payload: { completed: delete_runs })
    end

    private

    attr_reader :experiment, :max_rows, :runtime_limiter

    def delete_runs
      completed = true

      experiment.candidates.each_batch(of: BATCH_SIZE, column: :eid) do |candidates|
        completed = delete_run_children(candidates)
        break unless completed

        @deleted_rows += candidates.delete_all

        completed = !limit_reached?
        break unless completed
      end

      completed
    end

    # Deletes metrics, params and metadata first, so no statement cascades through whole runs.
    def delete_run_children(candidates)
      RUN_CHILDREN_SUB_BATCH_SIZES.each do |model, sub_batch_size|
        loop do
          deleted = model.for_candidates(candidates).limit(sub_batch_size).delete_all
          @deleted_rows += deleted
          sleep(BATCH_PAUSE)

          return false if limit_reached?
          break if deleted < sub_batch_size
        end
      end

      true
    end

    def limit_reached?
      deleted_rows >= max_rows || runtime_limiter.over_time?
    end
  end
end
