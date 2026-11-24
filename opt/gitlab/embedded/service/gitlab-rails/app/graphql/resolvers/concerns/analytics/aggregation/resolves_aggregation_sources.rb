# frozen_string_literal: true

# Resolves the groups and projects an aggregation engine aggregates data for.
# The including resolver must define `resource_ability`.
module Analytics
  module Aggregation
    module ResolvesAggregationSources
      extend ActiveSupport::Concern

      MAX_SOURCES = ::Types::Analytics::Aggregation::ScopeInputType::MAX_SOURCES

      IMPLICIT_SOURCE_CANDIDATES_LIMIT = 1_000
      IMPLICIT_SOURCE_CANDIDATES_BATCH_SIZE = 100

      NOT_AUTHORIZED_CODE =
        ::Resolvers::Analytics::Aggregation::AggregationFieldResolver::BaseAggregationFieldResolver::NOT_AUTHORIZED_CODE

      included do
        class_attribute :implicit_sources_finder_params, default: {}.freeze
      end

      private

      def aggregation_sources(arguments)
        scope = arguments[:descendants_scope] || {}
        group_paths = Array(scope[:group_full_paths])
        project_paths = Array(scope[:project_full_paths])

        case object
        when ::Project
          if group_paths.any? || project_paths.any?
            raise ::Gitlab::Graphql::Errors::ArgumentError,
              'groupFullPaths and projectFullPaths arguments are not supported at project level'
          end

          project_paths = [object.full_path]
        when ::Group
          group_paths = [object.full_path] if group_paths.empty? && project_paths.empty?
        else
          return organization_sources! if group_paths.empty? && project_paths.empty?
        end

        authorized_sources!(group_paths, project_paths)
      end

      def organization_sources!
        return [object] if Ability.allowed?(current_user, resource_ability, object)

        implicit_group_sources!
      end

      def implicit_group_sources!
        candidates = implicit_source_candidates
        raise_too_many_implicit_sources! if candidates.size > IMPLICIT_SOURCE_CANDIDATES_LIMIT

        sources = []

        candidates.each_slice(IMPLICIT_SOURCE_CANDIDATES_BATCH_SIZE) do |groups|
          ::Preloaders::GroupPolicyPreloader.new(groups, current_user).execute
          sources.concat(groups.select { |group| Ability.allowed?(current_user, resource_ability, group) })

          raise_too_many_implicit_sources! if sources.size > MAX_SOURCES
        end

        return sources if sources.any?

        raise_resource_not_available_error!(
          'No top-level groups with accessible analytics found. ' \
            'Use the groupFullPaths or projectFullPaths arguments.',
          { code: NOT_AUTHORIZED_CODE }
        )
      end

      def implicit_source_candidates
        params = { organization: object, **implicit_sources_finder_params }

        ::Analytics::Aggregation::ImplicitSourcesFinder.new(current_user, params)
          .execute
          .limit(IMPLICIT_SOURCE_CANDIDATES_LIMIT + 1)
          .to_a
      end

      def raise_too_many_implicit_sources!
        raise ::Gitlab::Graphql::Errors::ArgumentError,
          "Too many top-level groups to aggregate. Use the groupFullPaths or projectFullPaths arguments " \
            "to select at most #{MAX_SOURCES} sources."
      end

      def authorized_sources!(group_paths, project_paths)
        paths = (group_paths + project_paths).uniq(&:downcase)

        sources_by_path = load_sources(group_paths, project_paths)

        accessible, inaccessible = paths.partition do |path|
          source = sources_by_path[path.downcase]
          source && Ability.allowed?(current_user, resource_ability, source)
        end

        # Report all inaccessible sources identically to not disclose which ones exist.
        if inaccessible.any?
          raise_resource_not_available_error!(
            format(s_("AggregationEngine|The following sources are not accessible: %{source_ids}"),
              source_ids: inaccessible.join(', ')),
            { code: NOT_AUTHORIZED_CODE }
          )
        end

        accessible.map { |path| sources_by_path[path.downcase] }
      end

      def load_sources(group_paths, project_paths)
        sources = load_records(::Group, group_paths, ::Preloaders::GroupPolicyPreloader) +
          load_records(::Project, project_paths, ::Preloaders::ProjectPolicyPreloader)

        sources.index_by { |record| record.full_path.downcase }
      end

      def load_records(model_class, paths, preloader_class)
        return [] if paths.empty?

        records = source_scope(model_class).where_full_path_in(paths).to_a
        preloader_class.new(records, current_user).execute

        records
      end

      def source_scope(model_class)
        case object
        when ::Group
          model_class == ::Group ? object.self_and_descendants : object.all_projects
        when ::Project
          model_class.id_in(object.id)
        else
          model_class.in_organization(object)
        end
      end
    end
  end
end
