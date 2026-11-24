# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      class JobsInjector
        include Gitlab::Utils::StrongMemoize

        DuplicateJobNameError = Class.new(StandardError)

        def initialize(pipeline:, declared_stages:, on_conflict:, job_name_mappings: {})
          @pipeline = pipeline
          @declared_stages = declared_stages
          @rename_on_conflict = on_conflict
          @job_name_mappings = job_name_mappings

          @pipeline_jobs_by_name = pipeline.stages.flat_map(&:statuses).index_by(&:name)
          @pipeline_stages_by_name = pipeline.stages.index_by(&:name)
          @job_renames = {} # Keep track of all job renaming performed due to conflicts
          @jobs_with_needs = [] # Keep track of all jobs with `needs` that may require update due to the renaming
          @injected_job_names = Set.new # Keep track of the jobs injected here, to resolve `needs` against them first
          @all_policy_job_names = Set.new # Keep track of all policy job names, including jobs dropped with their stage
        end

        def inject_jobs(jobs:, stage:)
          # What: Claim the job's name here, before the stage check can drop it.
          # Why:  A `needs` on a dropped policy job must resolve to nothing,
          #       not to a same-named project job.
          @all_policy_job_names.merge(jobs.map(&:name))

          target_stage = ensure_stage_exists(stage)
          return unless target_stage

          jobs.each do |job|
            # We need to assign the new stage_idx for the jobs
            # because the source stages could have had different positions
            job.assign_attributes(pipeline: pipeline, stage_idx: target_stage.position)
            add_suffix(job: job)
            add_job(stage: target_stage, job: job)

            yield(job) if block_given?
          end

          update_needs_references!
          expand_references_for_parallelized_jobs!
        end

        private

        attr_reader :pipeline, :declared_stages, :pipeline_stages_by_name,
          :pipeline_jobs_by_name, :job_name_mappings

        def ensure_stage_exists(stage)
          existing_stage = pipeline_stages_by_name[stage.name]
          return existing_stage if existing_stage.present?
          return unless stage_declared_in_project_config?(stage)

          insert_stage_into_pipeline(stage).tap do |pipeline_stage|
            pipeline_stages_by_name[pipeline_stage.name] = pipeline_stage
          end
        end

        def declared_stages_positions
          declared_stages.each_with_index.to_h
        end
        strong_memoize_attr :declared_stages_positions

        def stage_declared_in_project_config?(stage)
          declared_stages_positions.key?(stage.name)
        end

        def insert_stage_into_pipeline(source_stage)
          source_stage.dup.tap do |target_stage|
            position = declared_stages_positions[target_stage.name]
            target_stage.assign_attributes(pipeline: pipeline, position: position)
            pipeline.stages << target_stage
          end
        end

        # Add suffix based on `rename_on_conflict` lambda. If it returns `nil`, no renaming is performed.
        # For parallelized jobs (e.g. `build 1/3`, `build: [aws]`), the suffix is applied to the base
        # name so that the trailing parallel marker remains at the end. This keeps the variants
        # grouped together in the UI (group_name strips the trailing marker).
        def add_suffix(job:)
          return unless pipeline_jobs_by_name.key?(job.name)

          original_name = job.name
          base_name = ::Gitlab::Utils::Job.group_name(original_name)
          parallel_suffix = ::Gitlab::Utils::Job.parallel_suffix(original_name)

          renamed_base = @rename_on_conflict&.call(base_name)
          return unless renamed_base

          job.name = "#{renamed_base}#{parallel_suffix}"
          @job_renames[original_name] = job.name
        end

        def add_job(stage:, job:)
          raise DuplicateJobNameError, "job names must be unique (#{job.name})" if pipeline_jobs_by_name.key?(job.name)

          stage.statuses << job
          pipeline_jobs_by_name[job.name] = job
          @injected_job_names << job.name
          @all_policy_job_names << job.name
          @jobs_with_needs << job if job.needs.present?
        end

        # Expand `needs` references that point to parallelized jobs (matrix or number parallel).
        # For example, if a policy job has `needs: [build]` and `build` was expanded to
        # `build: [aws]` and `build: [gcp]`, we expand the needs to reference all variants.
        #
        # Note: `dependencies` cannot be expanded because they don't support an `optional` attribute,
        # and validation happens during policy pipeline creation before jobs are merged.
        def expand_references_for_parallelized_jobs!
          return if job_name_mappings.blank?

          @jobs_with_needs.each do |job|
            job.needs = expand_needs_references(job.needs)
          end
        end

        def expand_needs_references(needs)
          needs.flat_map do |need|
            # Own-job needs stay untouched. Expanding them via the mapping table would
            # let the policy consume project artifacts under a name the policy itself declared.
            next [need] if @all_policy_job_names.include?(need.name)

            normalized_names = job_name_mappings[need.name.to_sym]
            next [need] if normalized_names.blank?

            # The same base name can be parallelized by both the policy and the project.
            # Prefer the policy's own variants when they exist.
            own_variants = normalized_names.select { |name| @injected_job_names.include?(name) }
            normalized_names = own_variants if own_variants.any?

            normalized_names.map { |normalized_name| need.dup.tap { |n| n.name = normalized_name } }
          end
        end

        def update_needs_references!
          return if @job_renames.blank? || @jobs_with_needs.blank?

          @jobs_with_needs.flat_map(&:needs).each do |need|
            need.name = @job_renames.fetch(need.name, need.name)
          end
        end
      end
    end
  end
end
