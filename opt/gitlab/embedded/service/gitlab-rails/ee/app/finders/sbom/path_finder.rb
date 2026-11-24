# frozen_string_literal: true

# Finds all dependency paths from a root node to target SBOM occurrence.
#
# This class performs a bottom-up depth-first search (DFS) traversal of the dependency graph
# to find all possible paths from root dependencies to a specified target occurrence.
# It supports cursor-based pagination for efficient handling of large dependency trees.
#
# The `sbom_graph_paths` table stores only the direct (parent to child) edges between
# SBOM occurrences. This class derives the full paths from those edges at read time.
# Root nodes are occurrences with no parents, or top-level ancestors.
#
# @example Basic usage
#   result = Sbom::PathFinder.execute(target_occurrence)
#   result[:paths] # Array of path objects with occurrence chains
#   result[:has_next_page] # Boolean indicating more results available
#   result[:has_previous_page] # Boolean indicating previous results available
#
# @example With pagination
#   # Forward pagination
#   result = Sbom::PathFinder.execute(
#     target_occurrence,
#     after_graph_ids: [1, 2, 3], # Cursor for pagination
#     limit: 10
#   )
#
#   # Backward pagination
#   result = Sbom::PathFinder.execute(
#     target_occurrence,
#     before_graph_ids: [4, 5, 6], # Cursor for pagination
#     limit: 10
#   )
#
# @see Sbom::GraphPath for the underlying graph structure
# @see Sbom::Occurrence for the dependency occurrence mode

# TODO: We should create a class to represent a dependency path
# and encapsulate cursor calculation in it too.
module Sbom
  class PathFinder
    include Gitlab::Utils::StrongMemoize

    MAX_LIMIT = 100

    attr_reader :occurrence, :after_graph_ids, :before_graph_ids, :limit
    attr_accessor :mode, :collector

    def self.execute(sbom_occurrence, after_graph_ids: [], before_graph_ids: [], limit: 20)
      new(sbom_occurrence, after_graph_ids: after_graph_ids, before_graph_ids: before_graph_ids, limit: limit).execute
    end

    def initialize(sbom_occurrence, after_graph_ids:, before_graph_ids:, limit:)
      @occurrence = sbom_occurrence
      @after_graph_ids = (after_graph_ids || []).reverse
      @before_graph_ids = (before_graph_ids || []).reverse
      @limit = (limit || 20).clamp(1, MAX_LIMIT)
      @cache_key_service = Sbom::LatestGraphTimestampCacheKey.new(project: @occurrence.project)
    end

    def execute
      result = Gitlab::Metrics.measure(:find_dependency_paths) do
        project_id = occurrence.project_id
        target_id = occurrence.id

        @graph = build_adjacency_list(project_id)
        @root_nodes = find_root_nodes
        paths_data = find_all_id_paths(target_id)
        occurrence_paths = convert_id_paths_to_occurrences(paths_data[:paths])

        {
          paths: occurrence_paths,
          has_previous_page: paths_data[:has_previous_page],
          has_next_page: paths_data[:has_next_page]
        }
      end

      record_metrics(result[:paths])
      result
    end

    private

    attr_accessor :graph, :root_nodes

    def build_adjacency_list(project_id)
      graph = {}
      @top_level_ancestor_ids = Set.new

      Sbom::GraphPath
        .by_project_and_timestamp(project_id, latest_timestamp)
        .each_batch(of: 1000) do |batch|
        batch.each do |path|
          graph[path.descendant_id] ||= []
          graph[path.descendant_id] << path.ancestor_id
          @top_level_ancestor_ids.add(path.ancestor_id) if path.top_level_ancestor
        end
      end

      # Sort the parents for consistent pagination
      graph.each_key do |key|
        graph[key].sort!
      end

      graph
    end

    def latest_timestamp
      read_timestamp_from_cache || Sbom::GraphPath.by_projects(occurrence.project_id).maximum(:created_at)
    end
    strong_memoize_attr :latest_timestamp

    def read_timestamp_from_cache
      @cache_key_service.retrieve
    end

    def find_root_nodes
      root_nodes = Set.new

      all_nodes = Set.new
      graph.each do |child, parent_list|
        all_nodes.add(child)
        parent_list.each { |parent| all_nodes.add(parent) }
      end

      # nodes which have no parents
      all_nodes.each do |node|
        root_nodes.add(node) if graph[node].nil? || graph[node].empty?
      end

      # Traversal only visits nodes reachable from the target, so every top-level parent in the
      # project is equivalent to the target's reachable ones. The target is excluded so its self
      # path comes only from should_add_top_level_path?.
      root_nodes + (@top_level_ancestor_ids - [occurrence.id])
    end

    def find_all_id_paths(target_id)
      @mode = if before_graph_ids.blank? && after_graph_ids.blank?
                :unscoped
              elsif before_graph_ids.any?
                :before
              else
                :after
              end

      collect_paths(target_id)
    end

    def collect_paths(target_id)
      @collector = create_collector

      traverse_graph(target_id, [], Set.new)

      if should_add_top_level_path?(@collector[:paths], occurrence)
        @collector[:paths].prepend({ path: [target_id], is_cyclic: false })
      end

      if @mode == :before
        has_previous_page = @collector[:paths].length > limit
        has_next_page = true
        paths = @collector[:paths].last(limit)
      else
        has_previous_page = @mode == :after
        has_next_page = @collector[:paths].length > limit
        paths = @collector[:paths].first(limit)
      end

      paths = [{ path: [target_id], is_cyclic: false }] if paths.empty? && @mode == :unscoped

      {
        paths: paths,
        has_previous_page: has_previous_page,
        has_next_page: has_next_page
      }
    end

    def create_collector
      {
        paths: [],
        cursor_found: false
      }
    end

    # Bottom-up DFS: start from target and find paths
    # to all root nodes.
    def traverse_graph(current, path_so_far, visited)
      current_path = path_so_far + [current]

      return if should_prune_branch?(current_path)

      return if handle_cursor_path(current_path)

      # If we've reached the target, we have a complete path.
      # Don't return here since this root node might be a top_level
      # node, which has parents.
      handle_path_finished(current_path, false) if @root_nodes.include?(current)

      # Skip if we've already visited this node on this path to avoid cycles
      if visited.include?(current)
        handle_cycle_detected(current_path)
        return
      end

      # Early termination checks
      return unless should_continue_traversal?

      # Continue traversal
      visited_for_branch = visited.clone.add(current)
      parents = graph[current] || []

      parents.each do |parent|
        break unless should_continue_traversal?

        traverse_graph(parent, current_path, visited_for_branch)
      end
    end

    # Checks if the current_path should be pruned based on after cursor.
    # In :after mode if a branch does not contain a path that is lexicographically equal or greater to after_graph_ids,
    # it should be pruned
    def should_prune_branch?(current_path)
      return false unless @mode == :after

      min_length = [current_path.length, after_graph_ids.length].min

      (0...min_length).each do |i|
        diff = current_path[i] <=> after_graph_ids[i]
        return true if diff < 0
        return false if diff > 0
      end

      # All compared elements are equal - don't prune as we might find the cursor or paths after it
      false
    end

    def handle_cursor_path(current_path)
      cursor_path = @mode == :after ? after_graph_ids : before_graph_ids

      if cursor_path.any? && paths_equal?(current_path, cursor_path)
        @collector[:cursor_found] = true
        true
      else
        false
      end
    end

    def handle_path_finished(current_path, is_cyclic)
      # reverse the array, since we traverse from target to roots
      path_entry = { path: current_path.reverse, is_cyclic: is_cyclic }

      # Add path based on mode and cursor status
      if @mode == :unscoped ||
          (@mode == :after && @collector[:cursor_found]) ||
          (@mode == :before && !@collector[:cursor_found])
        add_path_to_collector(path_entry)
      end
    end

    def handle_cycle_detected(current_path)
      handle_path_finished(current_path, true)
    end

    def add_path_to_collector(path_entry)
      if @mode == :before
        # Sliding window: keep only last limit+1 paths
        @collector[:paths] << path_entry
        @collector[:paths].shift if @collector[:paths].length > limit + 1
      else
        @collector[:paths] << path_entry
      end
    end

    def should_continue_traversal?
      if @mode == :before
        !@collector[:cursor_found]
      else
        @collector[:paths].length <= limit
      end
    end

    def paths_equal?(path1, path2)
      return false if path1.length != path2.length

      path1.each_with_index.all? { |node, i| node == path2[i] }
    end

    def convert_id_paths_to_occurrences(id_paths)
      all_ids = id_paths.flat_map { |item| item[:path] }.uniq
      occurrence_map = build_occurrence_map(all_ids)

      # Convert ID paths to occurrence paths, preserving cycle information
      id_paths.map do |item|
        {
          path: item[:path].map { |id| occurrence_map[id] },
          is_cyclic: item[:is_cyclic]
        }
      end
    end

    def build_occurrence_map(ids)
      occurrence_map = {}

      Sbom::Occurrence.id_in(ids).with_version.each_batch(of: 1000) do |batch|
        batch.each do |occurrence|
          occurrence_map[occurrence.id] = occurrence
        end
      end

      occurrence_map
    end

    # Add the self reference path if the target is top level and we are in unscoped mode.
    # If the path is already in the list, we skip adding it.
    # We add the self reference path at the front rather than at the end.
    # This is done to preserve pagination.
    def should_add_top_level_path?(paths, target_occurrence)
      return false unless target_occurrence.top_level? && @mode == :unscoped

      has_self_path = paths.any? do |p|
        p[:path].length == 1 && p[:path][0] == target_occurrence.id
      end

      !has_self_path
    end

    def record_metrics(paths)
      counter = Gitlab::Metrics.counter(
        :gitlab_dependency_paths_found_total,
        'Counts the number of ancestor dependency paths found for a given dependency.'
      )

      counter.increment(
        { cyclic: false },
        paths.count { |r| !r[:is_cyclic] }
      )
      counter.increment(
        { cyclic: true },
        paths.count { |r| r[:is_cyclic] }
      )
    end
  end
end
