# frozen_string_literal: true

module Sbom
  # Records the direct (path_length 1) edges between a project's SBOM occurrences.
  # Sbom::PathFinder derives full dependency paths and top-level ancestors from these edges.
  class BuildDependencyGraph
    include Gitlab::Utils::StrongMemoize

    BATCH_SIZE = 250

    def self.execute(project)
      new(project).execute
    end

    def initialize(project)
      @project = project
      @cache_key_service = Sbom::LatestGraphTimestampCacheKey.new(project: project)
      @all_paths = {}
    end

    def timestamp
      Time.zone.now
    end
    strong_memoize_attr :timestamp

    def execute
      create_graph_edges
      log_graph_complete
      new_graph = all_paths.values

      # This can raise ActiveRecord::RecordInvalid because another Ci::Pipeline can start removing Sbom::Occurrence
      # rows which will prevent this job from finishing successfully.
      #
      # This actually works in our favour since it's a clear indication we can leave the graph processing to the
      # newest job.
      bulk_insert_paths(new_graph)

      @cache_key_service.store(new_graph.first.created_at) unless new_graph.empty?

      # Schedule removal, this job is idempotent and deduplicated so we can schedule it many times
      Sbom::RemoveOldDependencyGraphsWorker.perform_async(project.id)
    end

    private

    attr_reader :project, :all_paths

    def create_graph_edges
      sbom_occurrences.each do |occurrence|
        next if occurrence.ancestors.empty?

        occurrence.ancestors.each do |ancestor|
          next if ancestor.empty?

          ancestor_name = ancestor['name']
          ancestor_version = ancestor['version']

          parent_occurrence = find_parent_sbom_occurrence(
            ancestor_name,
            ancestor_version,
            occurrence.input_file_path
          )

          next unless parent_occurrence

          collect(parent_occurrence.id, occurrence.id, parent_occurrence.top_level?)
        end
      end
    end

    def collect(ancestor_id, descendant_id, top_level)
      key = "#{ancestor_id}-#{descendant_id}"
      return if all_paths.has_key?(key)

      all_paths[key] = Sbom::GraphPath.new(
        ancestor_id: ancestor_id,
        descendant_id: descendant_id,
        project_id: project.id,
        path_length: 1,
        created_at: timestamp,
        updated_at: timestamp,
        top_level_ancestor: top_level
      )
    end

    def bulk_insert_paths(paths)
      paths.each_slice(BATCH_SIZE) do |slice|
        Sbom::GraphPath.bulk_insert!(slice)
      end
    end

    def sbom_occurrences
      Sbom::Occurrence.by_project_ids(project.id).with_version.order_by_id
    end
    strong_memoize_attr :sbom_occurrences

    # This is convoluted *but*:
    # `Sbom::Occurrence#ancestors` is `Array[Hash]`.
    # Every Hash is { "name": "something", "version": "something" }.
    # We need to find corresponding Sbom::Occurrence for that particular pair (Node, for example, allows two
    # versions of the same package in a single project)
    # This, usually, should give you exactly one record except it doesn't because monorepos are a thing
    # (it's perfectly fine to have two Rails applications depending on `activesupport`).
    def find_parent_sbom_occurrence(ancestor_name, ancestor_version, child_input_file_path)
      occurrence_index[[ancestor_name, child_input_file_path, ancestor_version]]
    end

    def occurrence_index
      sbom_occurrences.each_with_object({}) do |occurrence, index|
        # `||=` keeps the lowest id per key, matching the previous `find` over id-ordered occurrences.
        index[[occurrence.component_name, occurrence.input_file_path, occurrence.version]] ||= occurrence
      end
    end
    strong_memoize_attr :occurrence_index

    def log_graph_complete
      ::Gitlab::AppLogger.info(
        message: "New graph creation complete",
        project: project.name,
        project_id: project.id,
        namespace: project.namespace&.name,
        namespace_id: project.namespace&.id,
        count_path_nodes: all_paths.count
      )
    end
  end
end
