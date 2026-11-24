# frozen_string_literal: true

module Resolvers
  module Ci
    module Catalog
      module Resources
        class ProjectComponentUsagesResolver < BaseResolver
          include Gitlab::Graphql::Authorize::AuthorizeResource

          type [::Types::Ci::Catalog::Resources::ProjectUsageType], null: true

          argument :version_id, ::Types::GlobalIDType[::Ci::Catalog::Resources::Version],
            required: false,
            description: 'Filter to projects using a specific version of the catalog resource.'

          argument :version_ids, [::Types::GlobalIDType[::Ci::Catalog::Resources::Version]],
            required: false,
            description: 'Returns projects that used one or more specific versions of the catalog resource.'

          argument :component_name, GraphQL::Types::String,
            required: false,
            description: 'Filter to projects using a component with this name. ' \
              'Matches across all versions of the catalog resource.'

          argument :sort, ::Types::Ci::Catalog::Resources::ProjectUsageSortEnum,
            required: false,
            default_value: :oldest_version_asc,
            description: 'Sort projects by given criteria.'

          alias_method :catalog_resource, :object

          def resolve(sort: :oldest_version_asc, version_id: nil, version_ids: nil, component_name: nil)
            raise_resource_not_available_error! unless feature_available?
            return unless authorized?

            usages = fetch_usages(version_id: version_id, version_ids: version_ids, component_name: component_name)
            return [] if usages.empty?

            visible_projects = fetch_visible_projects(usages)
            return [] if visible_projects.empty?

            apply_sort(build_project_usages(usages, visible_projects), sort)
          end

          private

          def authorized?(**_args)
            Ability.allowed?(current_user, :read_project_component_usages, catalog_resource.project)
          end

          def feature_available?
            catalog_resource.project.root_ancestor
              .licensed_feature_available?(:ci_component_usages_in_projects)
          end

          def fetch_usages(version_id: nil, version_ids: nil, component_name: nil)
            scope = ::Ci::Catalog::Resources::Components::LastUsage
              .for_catalog_resource_with_component_versions(catalog_resource.id)

            scope = scope.by_version_id(version_id.model_id) if version_id
            scope = scope.by_version_ids(version_ids.map(&:model_id)) if version_ids.present?
            scope = scope.by_component_name(component_name) if component_name

            scope.to_a
          end

          def fetch_visible_projects(usages)
            project_ids = usages.map(&:used_by_project_id).uniq

            Project
              .id_in(project_ids)
              .public_or_visible_to_user(current_user)
              .non_archived
              .index_by(&:id)
          end

          def build_project_usages(usages, visible_projects)
            usages_by_project = usages
              .select { |u| visible_projects.key?(u.used_by_project_id) }
              .group_by(&:used_by_project_id)

            usages_by_project.map do |project_id, project_usages|
              build_project_usage(visible_projects[project_id], project_usages)
            end
          end

          def build_project_usage(project, project_usages)
            components_used = project_usages.map do |usage|
              {
                component: usage.component,
                version: usage.component.version,
                last_used_date: usage.last_used_date,
                outdated: older_than_latest?(usage.component.version)
              }
            end

            {
              project: project,
              components_used: components_used
            }
          end

          def older_than_latest?(version)
            return false unless version&.semver && latest_version&.semver

            version.semver < latest_version.semver
          end

          def latest_version
            @latest_version ||= catalog_resource.versions.latest
          end

          def apply_sort(project_usages, sort)
            case sort
            when :oldest_version_asc  then sort_by_semver(project_usages, :min, :asc)
            when :oldest_version_desc then sort_by_semver(project_usages, :min, :desc)
            when :version_asc         then sort_by_semver(project_usages, :max, :asc)
            when :version_desc        then sort_by_semver(project_usages, :max, :desc)
            when :last_used_asc       then sort_by_last_used(project_usages, :asc)
            when :last_used_desc      then sort_by_last_used(project_usages, :desc)
            when :project_name_asc    then sort_by_project_name(project_usages, :asc)
            when :project_name_desc   then sort_by_project_name(project_usages, :desc)
            else
              project_usages
            end
          end

          def sort_by_semver(project_usages, aggregate, direction)
            sorted = project_usages.sort_by do |entry|
              semvers = entry[:components_used].filter_map { |c| c[:version]&.semver }
              next Packages::SemVer.new(0, 0, 0) if semvers.empty?

              aggregate == :min ? semvers.min : semvers.max
            end
            direction == :asc ? sorted : sorted.reverse
          end

          def sort_by_last_used(project_usages, direction)
            sorted = project_usages.sort_by do |entry|
              entry[:components_used].map { |c| c[:last_used_date] }.max
            end
            direction == :asc ? sorted : sorted.reverse
          end

          def sort_by_project_name(project_usages, direction)
            sorted = project_usages.sort_by { |entry| entry[:project].name }
            direction == :asc ? sorted : sorted.reverse
          end
        end
      end
    end
  end
end
