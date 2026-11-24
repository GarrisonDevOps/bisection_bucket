# frozen_string_literal: true

module Resolvers
  module Ci
    module Catalog
      module Resources
        module Components
          class ProjectUsageResolver < BaseResolver
            include Gitlab::Graphql::Authorize::AuthorizeResource

            authorize_granular_token permissions: :read_ci_component_usage, boundary: :itself, boundary_type: :project

            type ::Types::Ci::Catalog::Resources::Components::UsageType.connection_type, null: true

            def resolve
              raise_resource_not_available_error! if !on_saas? && !available_on_self_hosted?

              BatchLoader::GraphQL.for(object.id).batch(default_value: []) do |project_ids, loader|
                projects = Project.with_namespaces.by_ids(project_ids)
                load_components_for_projects(projects, loader)
              end
            end

            private

            def on_saas?
              ::Gitlab::Saas.feature_available?(:ci_component_usages_in_projects)
            end

            def available_on_self_hosted?
              current_user&.can_admin_all_resources? &&
                License.feature_available?(:ci_component_usages_in_projects)
            end

            def load_components_for_projects(projects, loader)
              filtered_project_ids = filter_authorized_projects(projects)
              return if filtered_project_ids.empty?

              load_last_usages(filtered_project_ids, loader)
            end

            def filter_authorized_projects(projects)
              group_ids = projects.map { |p| p.namespace.id }
              licensed_and_authorized_group_ids = filter_authorized_groups(group_ids)

              projects
                .select { |p| licensed_and_authorized_group_ids.include?(p.namespace.id) }
                .map(&:id)
            end

            def filter_authorized_groups(group_ids)
              Group.id_in(group_ids).select do |group|
                authorized_for_group?(group)
              end.map(&:id)
            end

            def authorized_for_group?(group)
              return false unless group

              if on_saas? && group&.root_ancestor&.licensed_feature_available?(:ci_component_usages_in_projects)
                group.max_member_access_for_user(current_user) >= Gitlab::Access::MAINTAINER
              else
                available_on_self_hosted?
              end
            end

            def load_last_usages(project_ids, loader)
              ::Ci::Catalog::Resources::Components::LastUsage
                .by_project_ids(project_ids)
                .each { |project_id, components| loader.call(project_id, components) }
            end
          end
        end
      end
    end
  end
end
