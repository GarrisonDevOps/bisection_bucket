# frozen_string_literal: true

module Gitlab
  module Metrics
    module GlqlSlis
      include Gitlab::Metrics::SliConfig

      puma_enabled!

      FEATURE_CATEGORY = 'glql'
      # The caller_id of each route that runs Analytics::Glql::QueryService.
      UI_ENDPOINT = 'Glql::BaseController#execute'
      API_ENDPOINT = 'POST /api/:version/glql'
      ERROR_TYPES = [:query_aborted, :other, nil].freeze
      # Lets a service level cover GLQL queries from Duo Agent Platform tools on their own.
      DUO_AGENT_CLIENT = 'duo_agent'
      OTHER_CLIENT = 'other'

      class << self
        def initialize_slis!
          # Apdex is only recorded for queries that did not fail.
          Gitlab::Metrics::Sli::Apdex.initialize_sli(:glql, possible_labels(error_types: [nil]))
          Gitlab::Metrics::Sli::ErrorRate.initialize_sli(:glql, possible_labels(error_types: ERROR_TYPES))
        end

        # Builds the labels for one GLQL query. Recording and initialization both use it,
        # because a counter raises when a later increment has different label keys.
        #
        # @param endpoint_id [String] the caller_id of the route running the query
        # @param error_type [Symbol, nil] one of ERROR_TYPES
        # @param duo_agent [Boolean] whether a Duo Agent Platform tool sent the query
        # @return [Hash]
        def labels(endpoint_id:, error_type:, duo_agent:)
          {
            endpoint_id: endpoint_id,
            feature_category: FEATURE_CATEGORY,
            query_urgency: query_urgency.name,
            error_type: error_type,
            client: duo_agent ? DUO_AGENT_CLIENT : OTHER_CLIENT
          }
        end

        # The urgency GLQL queries are measured against.
        #
        # @return [Gitlab::EndpointAttributes::Config::RequestUrgency]
        def query_urgency
          Gitlab::EndpointAttributes::Config::REQUEST_URGENCIES.fetch(:low)
        end

        def record_apdex(labels:, success:)
          Gitlab::Metrics::Sli::Apdex[:glql].increment(labels: labels, success: success)
        end

        def record_error(labels:, error:)
          Gitlab::Metrics::Sli::ErrorRate[:glql].increment(labels: labels, error: error)
        end

        private

        def possible_labels(error_types:)
          endpoint_clients = []

          endpoint_clients += [[UI_ENDPOINT, false], [API_ENDPOINT, false]] if Gitlab::Metrics::Environment.api?
          # Workhorse runs Duo Agent Platform tool calls against the Rails in its own pod, on this fleet.
          endpoint_clients << [API_ENDPOINT, true] if Gitlab::Metrics::Environment.service?('ai-assisted')

          endpoint_clients.product(error_types).map do |(endpoint_id, duo_agent), error_type|
            labels(endpoint_id: endpoint_id, error_type: error_type, duo_agent: duo_agent)
          end
        end
      end
    end
  end
end
