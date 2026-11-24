# frozen_string_literal: true

module Govern
  module PolicyEngine
    module Impact
      # Dry run of a policy that is not saved yet, over the same candidate
      # projects the scheduled check would visit. The evaluator decides whether
      # a project violates the policy; this class only walks the candidates,
      # counts, lists the first violating ones and stops at the cap or the time
      # budget. Reads only.
      #
      # The resolver yields its inclusion arms one after the other, so the ids
      # are collected first and sorted: the cap and the listed sample then follow
      # one id order across the whole scope, not the order of the arms. Only the
      # smallest ids are kept, so memory stays bounded whatever the scope holds.
      class Analysis
        MAX_PROJECTS = 1_000
        MAX_LISTED_PROJECTS = 20
        TIME_BUDGET = 10.seconds
        # A scope with several arms cannot stop its id pass early, so the pass
        # gets half the budget and the evaluation always keeps the other half.
        ID_PASS_BUDGET = TIME_BUDGET / 2
        ID_BATCH_SIZE = 1_000
        PROJECT_BATCH_SIZE = 100

        def initialize(draft:, evaluator:)
          @draft = draft
          @evaluator = evaluator
          @projects_in_scope_count = 0
          @violating_count = 0
          @violating_projects = []
          @complete = true
        end

        def execute
          started_at = monotonic_time
          @id_deadline = started_at + ID_PASS_BUDGET
          @deadline = started_at + TIME_BUDGET

          candidate_ids.each_slice(PROJECT_BATCH_SIZE) do |ids|
            break unless evaluate_batch(ids)
          end

          Result.new(
            projects_in_scope_count: projects_in_scope_count, violating_count: violating_count,
            violating_projects: violating_projects, complete: complete, unavailable_reason: nil
          )
        end

        private

        attr_reader :draft, :evaluator, :projects_in_scope_count, :violating_count, :violating_projects, :complete

        # The smallest candidate ids, one past the cap so a scope that holds more
        # reads as incomplete, as does one whose ids were not all read in time.
        # A single-arm scope stops reading once that set is full: each_batch
        # yields ascending id ranges, so no later batch can enter it. Several
        # arms each restart at low ids, so the pass has to read them all.
        def candidate_ids
          ids = []
          stop_when_full = ScopeSupport.single_arm?(draft.policy_scope)

          ScopedProjectsResolver.new(draft).each_candidate_batch(of: ID_BATCH_SIZE) do |batch|
            break @complete = false if monotonic_time > @id_deadline

            ids = smallest(ids + batch.ids) # rubocop:disable CodeReuse/ActiveRecord -- the collection pass keeps ids only
            break if stop_when_full && ids.size > MAX_PROJECTS
          end

          @complete = false if ids.size > MAX_PROJECTS

          ids.first(MAX_PROJECTS)
        end

        def smallest(ids)
          ids.sort!.first(MAX_PROJECTS + 1)
        end

        # False once the time budget stops the run.
        def evaluate_batch(ids)
          # rubocop:disable CodeReuse/ActiveRecord -- loads the sorted slice with the evaluator's preloads
          projects = Project.id_in(ids).order(:id).preload(*preloads)
          # rubocop:enable CodeReuse/ActiveRecord

          projects.each do |project|
            if monotonic_time > @deadline
              @complete = false
              return false
            end

            evaluate(project)
          end

          true
        end

        def evaluate(project)
          @projects_in_scope_count += 1

          return unless evaluator.violates?(project)

          @violating_count += 1
          violating_projects << project if violating_projects.size < MAX_LISTED_PROJECTS
        end

        # The route serves the listed projects' paths; the rest is what the evaluator reads.
        def preloads
          [*evaluator.preloads, :route]
        end

        def monotonic_time
          ::Gitlab::Metrics::System.monotonic_time
        end
      end
    end
  end
end
