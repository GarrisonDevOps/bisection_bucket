# frozen_string_literal: true

module Sbom
  # Routes a dependency list request to the Sbom::OccurrenceRef Elasticsearch index or to
  # Postgres, and rejects an advanced filter that neither backend can answer.
  #
  # Including classes must supply #filterable_namespace, the Group or Project the request is
  # scoped to.
  #
  # Filters have to be keyed by symbol. A symbol Hash and ActionController::Parameters both
  # answer, but `params.permit(...).to_h` gives string keys and reads as no filter at all.
  #
  # Consumers call #validate_advanced_filters! first, then ask #use_elasticsearch? which
  # backend to use.
  module OccurrenceRefsFilterable
    extend ActiveSupport::Concern
    include ::Gitlab::Utils::StrongMemoize

    # Filters no Postgres finder can apply; asking for one is what moves a request onto
    # Elasticsearch.
    ADVANCED_FILTERS = %i[malware security_project_tracked_context_id tracked_refs_scope].freeze

    # The resolver renames `trackedRefIds` on the way in, so an error has to name the argument the
    # caller actually passed rather than the internal one.
    FILTER_ARGUMENT_NAMES = { security_project_tracked_context_id: :tracked_ref_ids }.freeze

    private

    # The Postgres fallback drops an advanced filter rather than applying it, so an
    # unavailable filter has to fail loudly instead of answering with an unfiltered list.
    def validate_advanced_filters!(filters)
      requested = requested_advanced_filters(filters)

      return if requested.empty?

      validate_policy_violations_conflict!(requested, filters)

      unavailable = unavailable_advanced_filters(requested)
      return if unavailable.empty?

      noun = 'filter'.pluralize(unavailable.size)
      verb = unavailable.size == 1 ? 'is' : 'are'

      raise ::Gitlab::Graphql::Errors::ArgumentError,
        "The #{argument_names(unavailable).to_sentence} #{noun} #{verb} not available."
    end

    # No backend can handle both: Elasticsearch supports advanced filters but lacks
    # policy_violations data; Postgres has policy_violations but lacks advanced filters.
    def validate_policy_violations_conflict!(requested, filters)
      return if filters[:policy_violations].blank?

      raise ::Gitlab::Graphql::Errors::ArgumentError,
        "The policy_violations filter cannot be combined with the #{argument_names(requested).to_sentence} filter."
    end

    def use_elasticsearch?(filters)
      requested = requested_advanced_filters(filters)

      requested.any? && unavailable_advanced_filters(requested).empty?
    end

    def argument_names(filters)
      filters.map { |filter| FILTER_ARGUMENT_NAMES.fetch(filter, filter) }
    end

    # `malware: false` and an explicit `malware: null` are filters in their own right, so key
    # presence, not the value, decides whether the client asked for one.
    def requested_advanced_filters(filters)
      ADVANCED_FILTERS.select { |filter| filters.key?(filter) }
    end

    def unavailable_advanced_filters(requested)
      return requested unless advanced_filters_available?

      requested.reject { |filter| filter_available?(filter) }
    end

    # No separate index-readiness check: Sbom::AdvancedDependencyManagementPolicy already
    # prevents this ability when the OccurrenceRef index cannot serve reads.
    def advanced_filters_available?
      ::Ability.allowed?(current_user, :read_advanced_dependency_management, filterable_namespace)
    end
    strong_memoize_attr :advanced_filters_available?

    def filter_available?(filter)
      case filter
      when :malware
        true
      when :security_project_tracked_context_id, :tracked_refs_scope
        Feature.enabled?(:project_dependency_tracked_ref, filterable_namespace, type: :wip)
      else
        false
      end
    end

    def filterable_namespace
      raise NotImplementedError, "#{self.class} must implement #filterable_namespace"
    end
  end
end
