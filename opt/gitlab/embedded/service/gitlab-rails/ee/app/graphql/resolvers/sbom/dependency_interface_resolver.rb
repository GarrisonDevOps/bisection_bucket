# frozen_string_literal: true

module Resolvers
  module Sbom
    class DependencyInterfaceResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include Gitlab::InternalEventsTracking
      include LooksAhead
      include ::Security::MalwareTrackedRefsValidation

      SORT_TO_PARAMS_MAP = {
        name_desc: { sort_by: 'name', sort: 'desc' },
        name_asc: { sort_by: 'name', sort: 'asc' },
        packager_desc: { sort_by: 'packager', sort: 'desc' },
        packager_asc: { sort_by: 'packager', sort: 'asc' },
        severity_desc: { sort_by: 'severity', sort: 'desc' },
        severity_asc: { sort_by: 'severity', sort: 'asc' },
        license_asc: { sort_by: 'license', sort: 'asc' },
        license_desc: { sort_by: 'license', sort: 'desc' }
      }.freeze

      authorize :read_dependency
      authorizes_object!

      type Types::Sbom::DependencyInterface.connection_type, null: true

      argument :sort, Types::Sbom::DependencySortEnum,
        required: false,
        description: 'Sort dependencies by given criteria.'

      argument :package_managers, [Types::Sbom::PackageManagerEnum],
        required: false,
        description: 'Filter dependencies by package managers.'

      argument :component_names, [GraphQL::Types::String],
        required: false,
        description: 'Filter dependencies by component names.'

      argument :component_ids, [Types::GlobalIDType[::Sbom::Component]],
        required: false,
        description: 'Filter dependencies by component IDs.'

      argument :source_types, [Types::Sbom::SourceTypeEnum],
        required: false,
        default_value: ::Sbom::Source::DEFAULT_SOURCES.keys.map(&:to_s) + ['nil_source'],
        description: 'Filter dependencies by source type.'

      argument :component_versions, [GraphQL::Types::String],
        required: false,
        description: 'Filter dependencies by component versions.'

      argument :licenses, [GraphQL::Types::String],
        required: false,
        experiment: { milestone: '19.2' },
        description: 'Filter dependencies by SPDX license identifiers.'

      argument :not_component_versions, [GraphQL::Types::String],
        required: false,
        description: 'Filter dependencies to exclude the specified component versions.',
        experiment: { milestone: '18.1' }

      validates mutually_exclusive: [:component_names, :component_ids]

      argument :policy_violations, [::Types::SecurityOrchestration::PolicyViolationsEnum],
        required: false,
        experiment: { milestone: '18.7' },
        description: 'Filter by security policy violations. Cannot be combined with the ' \
          '`malware` argument.'

      argument :tracked_ref_ids, [::Types::GlobalIDType[::Security::ProjectTrackedContext]],
        as: :security_project_tracked_context_id,
        prepare: ->(ids, _) { Array(ids).map(&:model_id) },
        required: false,
        experiment: { milestone: '19.0' },
        description: 'Filter dependencies by tracked ref IDs. ' \
          'Applied only on `Project.dependencies`, and ignored on other fields. ' \
          'Requires advanced search configured, advanced dependency management set up, and ' \
          'the `vulnerabilities_across_contexts` and `project_dependency_tracked_ref` ' \
          'feature flags enabled; the request is rejected otherwise.'

      argument :tracked_refs_scope, ::Types::Security::TrackedRefScopeEnum,
        required: false,
        experiment: { milestone: '19.0' },
        description: 'Filter dependencies by tracked ref scope. ' \
          'Applied only on `Project.dependencies`, and ignored on other fields. ' \
          'Requires advanced search configured, advanced dependency management set up, and ' \
          'the `vulnerabilities_across_contexts` and `project_dependency_tracked_ref` ' \
          'feature flags enabled; the request is rejected otherwise.'

      argument :malware, GraphQL::Types::Boolean,
        required: false,
        description: 'Filter dependencies by malware status. ' \
          'Cannot be combined with `trackedRefsScope: ALL_REFS` or with ' \
          '`trackedRefIds` referring to a non-default-branch ref.'

      alias_method :project_or_namespace, :object

      def resolve_with_lookahead(**args)
        return ::Sbom::Occurrence.none unless project_or_namespace

        validate_tracked_context_args!(args)
        validate_malware_tracked_refs_conflict!(malware_filter_actor, args)

        context.scoped_set!(:sbom_tracked_ref_filter, tracked_ref_filter(args))

        args[:component_ids] = resolve_gids(args[:component_ids], ::Sbom::Component) if args[:component_ids]

        list = dependencies(args)

        track_event

        paginate(list)
      end

      def preloads
        {
          name: [:component],
          version: [:component_version],
          component_version: [:component_version],
          packager: [:source],
          location: [:source],
          vulnerabilities: [:vulnerabilities],
          malware: [:component, :component_version]
        }
      end

      private

      def paginate(list)
        offset_pagination(list)
      end

      def tracked_ref_filter(args)
        return {} unless project_or_namespace.is_a?(::Project)

        args.slice(:security_project_tracked_context_id, :tracked_refs_scope)
      end

      def validate_tracked_context_args!(args)
        return if (args.keys & %i[security_project_tracked_context_id tracked_refs_scope]).blank?

        actor = project_or_namespace.is_a?(::Project) ? project_or_namespace.root_namespace : Feature.current_request
        return if Feature.enabled?(:vulnerabilities_across_contexts, actor)

        raise ::Gitlab::Graphql::Errors::ArgumentError,
          'The vulnerabilities_across_contexts feature flag is not enabled.'
      end

      def resolve_gids(gids, gid_class)
        gids.map do |gid|
          Types::GlobalIDType[gid_class].coerce_isolated_input(gid).model_id
        end
      end

      def dependencies(params)
        raise NotImplementedError, "#{self.class.name} does not implement dependencies"
      end

      # Only `Search::AdvancedFinders::Sbom::DependenciesFinder` understands `:malware`, so the
      # Postgres finders leave `include_malware` off and the argument is stripped instead.
      def mapped_params(params, include_malware: false)
        result = params.except(:sort, :not_component_versions)
        result.delete(:malware) unless include_malware
        result.merge!(SORT_TO_PARAMS_MAP.fetch(params[:sort], {}))

        if params[:not_component_versions].present?
          result[:not] =
            { component_versions: params[:not_component_versions] }
        end

        result
      end

      def malware_filter_actor
        project_or_namespace.try(:project) || project_or_namespace
      end

      def track_event
        if project_or_namespace.is_a?(::Project)
          track_internal_event(
            "called_dependency_api",
            user: current_user,
            project: project_or_namespace,
            additional_properties: {
              label: 'graphql'
            }
          )
        elsif project_or_namespace.is_a?(::Group)
          track_internal_event(
            "called_dependency_api",
            user: current_user,
            namespace: project_or_namespace,
            additional_properties: {
              label: 'graphql'
            }
          )
        end
      end
    end
  end
end
