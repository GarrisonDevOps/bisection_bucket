# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module GroupedEvaluatorConcern
      extend ActiveSupport::Concern

      VULNERABILITY_ATTRIBUTE_KEYS = %i[fix_available false_positive known_exploited].freeze

      included do
        attr_reader :project, :params
      end

      private

      def group_scanners_by_attributes
        return {} unless scanner_configurations

        scanner_configurations
          .group_by { |config| normalize_group_key(config) }
          .transform_values { |configs| extract_scanner_types(configs) }
      end

      def normalize_group_key(config)
        vuln_attrs = normalize_vulnerability_attributes(config[:vulnerability_attributes] || {})

        group_key_mapping.each_with_object(vuln_attrs) do |(config_key, param_key), result|
          result[param_key] = config.key?(config_key) ? config[config_key] : params[param_key]
        end.compact
      end

      def group_key_mapping
        raise NotImplementedError, "#{self.class} must implement #group_key_mapping"
      end

      def extract_scanner_types(configs)
        configs.pluck(:type) # rubocop:disable CodeReuse/ActiveRecord -- configs is an array of hashes, not AR
      end

      def normalize_vulnerability_attributes(attributes)
        attrs = attributes.deep_symbolize_keys

        result = VULNERABILITY_ATTRIBUTE_KEYS.index_with do |key|
          attrs.key?(key) ? attrs[key] : params[key]
        end

        result[:epss_score] = normalize_epss_score(attrs.key?(:epss_score) ? attrs[:epss_score] : params[:epss_score])
        result[:enrichment_data_unavailable_action] = if attrs.key?(:enrichment_data_unavailable)
                                                        attrs.dig(:enrichment_data_unavailable, :action)
                                                      else
                                                        params[:enrichment_data_unavailable_action]
                                                      end

        result.compact
      end

      def normalize_epss_score(epss_score)
        return unless epss_score.is_a?(Hash)

        epss_score.deep_symbolize_keys
      end

      def vulnerability_attributes_from(source)
        VULNERABILITY_ATTRIBUTE_KEYS.index_with do |key|
          source[key]
        end.merge(
          epss_score: source[:epss_score],
          enrichment_data_unavailable_action: source[:enrichment_data_unavailable_action]
        ).compact
      end

      def scanner_configurations
        params[:scanner_configurations]
      end
    end
  end
end
