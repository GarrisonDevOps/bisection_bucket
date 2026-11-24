# frozen_string_literal: true

module Search
  module Zoekt
    class RoutingService
      MAX_NUMBER_OF_PROJECTS = 30_000

      attr_reader :projects

      def self.execute(...)
        new(...).execute
      end

      def initialize(projects)
        @projects = projects
      end

      # Generates a routing map of zoekt nodes to project ids
      # this is needed to send search requests to appropriate nodes
      # @returns [Hash] { node_id => [1,2,3], node_id2 => [4,5,6] }
      # rubocop:disable CodeReuse/ActiveRecord -- this service builds a complex custom AR query
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- we restrict the number of projects in the guard clause
      def execute
        raise "Too many projects" if projects.count > MAX_NUMBER_OF_PROJECTS

        result = fetch_projects_through_replicas.pluck(:id, :zoekt_node_id)

        mapped_result = result.group_by(&:last).transform_values { |v| v.map(&:first) }
        sorted = mapped_result.sort_by { |_, v| v.count }.reverse

        {}.tap do |hash|
          processed = Set.new
          sorted.each do |node_id, project_ids|
            project_ids.each do |project_id|
              next if processed.include?(project_id)

              hash[node_id] ||= []
              hash[node_id] << project_id
              processed << project_id
            end
          end
        end
      end

      private

      def fetch_projects_through_replicas
        projects.without_order
          .joins(zoekt_repositories: { zoekt_index: [{ replica: :zoekt_enabled_namespace }, :node] })
          .merge(EnabledNamespace.search_enabled)
          .merge(Replica.ready)
          .merge(Node.for_search.searchable)
      end
      # rubocop:enable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit
    end
  end
end
