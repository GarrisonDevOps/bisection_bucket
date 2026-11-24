# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        # This caller sends the query plus a feature catalog to the AI Gateway
        # (Gemini by default) and returns the ordered list of matching feature IDs.
        # Unlike most completions this runs synchronously and returns the parsed IDs
        class FeatureDiscoverySearch < Base # rubocop:disable Search/NamespacedClass -- "Search" means feature discovery
          extend ::Gitlab::Utils::Override

          PROMPT_VERSION = '^1.0.0'

          # Returns the ordered Array of feature IDs the model matched, intersected
          # with the catalog we sent (defends against hallucinated IDs). Returns []
          # on any error so the caller degrades to "no results", never an exception.
          override :execute
          def execute
            return [] unless valid?

            Gitlab::AiGateway.push_feature_flag(:feature_discovery_gemini_search, user)

            response = request!
            parse_feature_ids(response)
          end

          override :inputs
          def inputs
            { query: query, catalog: catalog }
          end

          override :root_namespace
          def root_namespace
            resource.try(:root_ancestor)
          end

          private

          override :prompt_version
          def prompt_version
            PROMPT_VERSION
          end

          override :ai_gateway_timeout
          def ai_gateway_timeout
            5.seconds
          end

          override :valid?
          def valid?
            super && query.present? && catalog.present?
          end

          def query
            options[:query]
          end

          def catalog
            options[:catalog]
          end

          def parse_feature_ids(response)
            ids = extract_ids(response)
            return [] if ids.empty?

            # Preserve the model-provided order, keep only IDs we actually offered.
            known_ids = catalog.map { |feature| feature[:id].to_s }
            ids.map(&:to_s).uniq.select { |id| known_ids.include?(id) }
          rescue StandardError => e
            Gitlab::ErrorTracking.track_exception(e, ai_action: prompt_message.ai_action)
            []
          end

          def extract_ids(response)
            parsed = response.is_a?(String) ? Gitlab::Json.safe_parse(response) : response

            case parsed
            when Array
              parsed
            when Hash
              parsed['feature_ids'] || parsed['features'] || []
            else
              []
            end
          end
        end
      end
    end
  end
end
