# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Loads what WorkflowPolicy reads on each session's project or group
    # so a page of sessions is authorized without one query per container.
    class WorkflowPolicyPreloader
      def initialize(workflows, current_user)
        @workflows = workflows
        @current_user = current_user
      end

      def execute
        projects = workflows.filter_map(&:project).uniq
        groups = workflows.filter_map(&:namespace).grep(::Group).uniq

        ActiveRecord::Associations::Preloader.new(
          records: projects,
          associations: [:project_setting, :organization, :project_namespace, :group, :namespace]
        ).call
        ActiveRecord::Associations::Preloader.new(
          records: groups,
          associations: [:organization, :namespace_settings]
        ).call

        ::Preloaders::UserMaxAccessLevelInProjectsPreloader.new(projects, current_user).execute
        ::Preloaders::UserMaxAccessLevelInGroupsPreloader.new(groups, current_user).execute

        share_root_ancestors(projects.map(&:namespace) + projects.filter_map(&:group) + groups)

        ::Ai::DuoWorkflows::Workflow.prime_last_workload_pipeline_statuses(workflows)
      end

      private

      attr_reader :workflows, :current_user

      # `uniq` by object: AR equality is by id, and the same group can appear as
      # `project.namespace`, `project.group` and `workflow.namespace` instances.
      def share_root_ancestors(namespaces)
        namespaces = namespaces.uniq(&:object_id)
        # `:route` is read by `Gitlab::UrlBuilder#duo_workflow_url` through `root_ancestor.full_path`.
        roots = ::Namespace.id_in(namespaces.map { |ns| ns.traversal_ids.first }.uniq)
          .preload(:namespace_settings, :ai_settings, :route)
          .index_by(&:id)
        # Only groups have a SAML provider; a personal project's root is a user namespace.
        ActiveRecord::Associations::Preloader.new(
          records: roots.values.grep(::Group),
          associations: :saml_provider
        ).call

        namespaces.each do |namespace|
          namespace.root_ancestor = roots[namespace.traversal_ids.first]
        end
      end
    end
  end
end
