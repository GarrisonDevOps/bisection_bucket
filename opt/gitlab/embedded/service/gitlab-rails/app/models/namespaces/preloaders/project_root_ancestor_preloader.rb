# frozen_string_literal: true

module Namespaces
  module Preloaders
    class ProjectRootAncestorPreloader
      def initialize(projects, namespace_sti_name = :namespace, root_ancestor_preloads = [])
        @projects = projects
        @namespace_sti_name = namespace_sti_name
        @root_ancestor_preloads = root_ancestor_preloads
      end

      def execute
        return if @projects.is_a?(ActiveRecord::Relation) ? @projects.null_relation? : @projects.empty?

        ActiveRecord::Associations::Preloader.new(records: @projects, associations: :namespace).call

        @projects.is_a?(ActiveRecord::Relation) ? preload_for_relation : preload_for_array
      end

      private

      def preload_for_relation
        root_query = Namespace.joins("INNER JOIN (#{join_sql}) as root_query ON root_query.root_id = namespaces.id")
                          .select('namespaces.*, root_query.project_id as source_id')

        root_ancestors_by_id = with_preloads(root_query).group_by(&:source_id)

        @projects.each do |project|
          root_ancestor = root_ancestors_by_id[project.id]&.first
          project.namespace.root_ancestor = root_ancestor if root_ancestor.present?
        end
      end

      # The projects are already loaded, so read root IDs from their namespaces instead of
      # joining. This keeps the IN-list bounded by distinct top-level groups, not projects.
      def preload_for_array
        namespaces_by_root_id = @projects.each_with_object(Hash.new { |h, k| h[k] = [] }) do |project, hash|
          namespace = project.namespace
          next if namespace.nil? || (@namespace_sti_name == :group && !namespace.group_namespace?)

          hash[namespace.traversal_ids.first] << namespace
        end

        with_preloads(Namespace.id_in(namespaces_by_root_id.keys)).each do |root_ancestor|
          namespaces_by_root_id[root_ancestor.id].each { |namespace| namespace.root_ancestor = root_ancestor }
        end
      end

      def with_preloads(query)
        @root_ancestor_preloads.any? ? query.preload(*@root_ancestor_preloads) : query
      end

      def join_sql
        @projects
          .joins(@namespace_sti_name)
          .select('projects.id as project_id, namespaces.traversal_ids[1] as root_id')
          .to_sql
      end
    end
  end
end
