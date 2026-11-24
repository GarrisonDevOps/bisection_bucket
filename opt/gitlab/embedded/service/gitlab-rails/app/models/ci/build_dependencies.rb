# frozen_string_literal: true

module Ci
  class BuildDependencies
    include ::Gitlab::Utils::StrongMemoize

    attr_reader :processable

    def initialize(processable)
      @processable = processable
    end

    def all
      (local + cross_pipeline + cross_project).uniq
    end

    def invalid
      [local, cross_pipeline, cross_project].flat_map { |deps| deps.reject(&:valid_dependency?) }
    end

    def valid?
      valid_local? && valid_cross_pipeline? && valid_cross_project?
    end

    private

    # Dependencies can only be of Ci::Build type because only builds
    # can create artifacts
    def model_class
      ::Ci::Build
    end

    # Dependencies local to the given pipeline
    def local
      strong_memoize(:local) do
        next [] if no_local_dependencies_specified?
        next [] unless processable.pipeline_id # we don't have any dependency when creating the pipeline

        deps = model_class.where(pipeline_id: processable.pipeline_id, partition_id: processable.partition_id).latest
        deps = find_dependencies(processable, deps)

        from_dependencies(deps).to_a
      end
    end

    def find_dependencies(processable, deps)
      if processable.scheduling_type_dag?
        from_needs(deps)
      else
        from_previous_stages(deps)
      end
    end

    # Dependencies from the same parent-pipeline hierarchy excluding
    # the current job's pipeline. Only successful jobs can provide artifacts,
    # so we filter the (any-status) hierarchy jobs down to successful ones.
    def cross_pipeline
      existing_cross_pipeline_dependencies.select(&:success?)
    end
    strong_memoize_attr :cross_pipeline

    # Dependencies that are defined by project and ref
    def cross_project
      []
    end

    # All jobs (any status) in the pipeline hierarchy matching the specified cross-pipeline dependencies.
    def existing_cross_pipeline_dependencies
      return [] if expanded_cross_pipeline_dependencies.empty?

      jobs_in_pipeline_hierarchy(expanded_cross_pipeline_dependencies, model_class.latest)
    end
    strong_memoize_attr :existing_cross_pipeline_dependencies

    def jobs_in_pipeline_hierarchy(deps_specifications, scope)
      in_pipeline_hierarchy(scope, deps_specifications)
        .by_name(deps_specifications.map { |spec| spec[:job] }.uniq)
        .select do |dependency|
          # the query may not return exact matches pipeline-job, so we filter
          # them separately.
          deps_specifications.find do |spec|
            spec[:pipeline] == dependency.pipeline_id &&
              spec[:job] == dependency.name
          end
        end
    end

    # Flag off = master queries. Flag on = prune by (commit_id, partition_id) pairs.
    def in_pipeline_hierarchy(scope, deps_specifications)
      unless prune_partitions?
        pipeline_ids = deps_specifications.map { |spec| spec.fetch(:pipeline) }.uniq
        return scope.in_pipelines(same_family_pipeline_ids).in_pipelines(pipeline_ids)
      end

      return scope.none if cross_pipeline_pairs.empty?

      scope.where([:commit_id, :partition_id] => cross_pipeline_pairs)
    end

    # Replaces the inline same_family_pipeline_ids check in valid_cross_pipeline?, behind the same flag.
    def all_pipelines_in_hierarchy?(pipeline_ids)
      return (pipeline_ids - cross_pipeline_pairs.map(&:first)).empty? if prune_partitions?

      same_family_pipeline_ids.where(id: pipeline_ids).count == pipeline_ids.size
    end

    def same_family_pipeline_ids
      processable.pipeline.same_family_pipeline_ids
    end
    strong_memoize_attr :same_family_pipeline_ids

    def prune_partitions?
      Feature.enabled?(:ci_cross_pipeline_deps_partition_pruning, project)
    end
    strong_memoize_attr :prune_partitions?

    # (id, partition_id) of the requested pipelines that are in this pipeline's hierarchy.
    # The limit lets the query stop once every requested id is found.
    def cross_pipeline_pairs
      ids = expanded_cross_pipeline_dependencies.map { |spec| spec.fetch(:pipeline) }.uniq

      same_family_pipeline_pairs.where(pipeline_id: ids).limit(ids.size).pluck(:pipeline_id, :partition_id)
    end
    strong_memoize_attr :cross_pipeline_pairs

    # Only child pipelines walk up to the root; other same-project sources must not widen the family.
    def same_family_pipeline_pairs
      return same_project_hierarchy.family_objects if processable.pipeline.parent_pipeline?

      same_project_hierarchy.base_and_descendants
    end

    def same_project_hierarchy
      ::Gitlab::Ci::PipelineSourceHierarchy.new(processable.pipeline, options: { project_condition: :same })
    end

    def expanded_cross_pipeline_dependencies
      specified_cross_pipeline_dependencies.filter_map do |spec|
        pipeline = ExpandVariables.expand(spec[:pipeline].to_s, processable_variables).to_i
        # current pipeline is not allowed because local dependencies
        # should be used instead.
        next if pipeline == processable.pipeline_id

        job = ExpandVariables.expand(spec[:job], processable_variables)

        { job: job, pipeline: pipeline, optional: !!spec[:optional] }
      end
    end
    strong_memoize_attr :expanded_cross_pipeline_dependencies

    # Required jobs must succeed. Optional jobs may be absent but must target
    # a valid pipeline, and any existing job must still succeed.
    def valid_cross_pipeline?
      # Current-pipeline dependencies are omitted during expansion but remain invalid here.
      return false unless expanded_cross_pipeline_dependencies.size == specified_cross_pipeline_dependencies.size

      missing_dependencies = expanded_cross_pipeline_dependencies.reject do |spec|
        existing_cross_pipeline_dependencies.any? do |dependency|
          dependency.success? && spec[:pipeline] == dependency.pipeline_id && spec[:job] == dependency.name
        end
      end

      # Missing required dependencies invalidates the build.
      return false if missing_dependencies.any? { |spec| !spec[:optional] }
      return true if missing_dependencies.empty?

      # Missing optional dependencies must still target the same pipeline hierarchy.
      pipeline_ids = missing_dependencies.map { |spec| spec.fetch(:pipeline) }.uniq
      return false unless all_pipelines_in_hierarchy?(pipeline_ids)

      # Optionality permits absent jobs, not existing jobs that failed.
      existing_cross_pipeline_dependencies.all?(&:success?)
    end

    def valid_local?
      local.all?(&:valid_dependency?)
    end

    def valid_cross_project?
      true
    end

    def project
      processable.project
    end

    def no_local_dependencies_specified?
      processable.options[:dependencies]&.empty?
    end

    def from_previous_stages(scope)
      scope.before_stage(processable.stage_idx)
    end

    def from_needs(scope)
      needs_names = processable.needs.artifacts.select(:name)
      scope.where(name: needs_names)
    end

    def from_dependencies(scope)
      return scope unless processable.options[:dependencies].present?

      scope.where(name: processable.options[:dependencies])
    end

    def processable_variables
      -> { processable.simple_variables_without_dependencies }
    end

    def specified_cross_pipeline_dependencies
      strong_memoize(:specified_cross_pipeline_dependencies) do
        specified_cross_dependencies.select { |dep| dep[:pipeline] && dep[:artifacts] }
      end
    end

    def specified_cross_dependencies
      Array(processable.options[:cross_dependencies])
    end
  end
end

Ci::BuildDependencies.prepend_mod_with('Ci::BuildDependencies')
