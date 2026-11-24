# frozen_string_literal: true

module EE
  module Gitlab
    module Metrics
      module GlobalSearchSlis
        def self.prepended(base)
          base.singleton_class.prepend(ClassMethods)
        end

        SEMANTIC_SEARCH_TYPE = 'semantic'
        SEMANTIC_SEARCH_LEVEL = 'project'
        SEMANTIC_SEARCH_SCOPE = 'blobs'
        SEMANTIC_ENDPOINT_ID = 'GET /api/:version/projects/:id/(-/)search/semantic'

        # Chosen to match the `urgency :low` the endpoint already declares, which
        # Gitlab::EndpointAttributes::Config::REQUEST_URGENCIES maps to 5s. That keeps this
        # SLI and the rails_request apdex for the same endpoint agreeing on one threshold
        # instead of grading identical requests two different ways.
        #
        # It is intentionally NOT derived from the code-search constants (ZOEKT_TARGET_S,
        # ADVANCED_CODE_TARGET_S), which are 99.95th percentiles measured from production
        # logs. No such percentile exists for this endpoint yet - this MR adds the metric
        # that would produce it. Retune from real data, and the endpoint's urgency with it,
        # once the series has traffic: gitlab-org/gitlab#627671.
        SEMANTIC_TARGET_S = 5

        module ClassMethods
          extend ::Gitlab::Utils::Override

          override :endpoint_ids
          def endpoint_ids
            endpoints = super

            endpoints.push('SearchController#aggregations') if ::Gitlab::Metrics::Environment.web?

            endpoints
          end

          # Both overrides below are private to match the visibility in the prepended base.
          private

          # Without this override 'semantic' falls through to DEFAULT_TARGET_S: the same 5s, but
          # by accident, and a change to DEFAULT_TARGET_S would silently move it. Overriding the
          # derivation rather than `duration_target` keeps semantic inside the CE spec's guard.
          override :derived_duration_target
          def derived_duration_target(search_type, search_scope)
            return SEMANTIC_TARGET_S if search_type == SEMANTIC_SEARCH_TYPE

            super
          end

          # Registered as its own combination rather than through the search_type x search_level
          # x search_scope cross product in `possible_labels`: 'semantic' is served by exactly
          # one endpoint, so the cross product would mint labels that can never be observed.
          override :possible_labels
          def possible_labels
            super + semantic_labels
          end

          def semantic_labels
            return [] unless ::Gitlab::Metrics::Environment.api?

            [{
              search_type: SEMANTIC_SEARCH_TYPE,
              search_level: SEMANTIC_SEARCH_LEVEL,
              search_scope: SEMANTIC_SEARCH_SCOPE,
              endpoint_id: SEMANTIC_ENDPOINT_ID
            }]
          end
        end
      end
    end
  end
end
