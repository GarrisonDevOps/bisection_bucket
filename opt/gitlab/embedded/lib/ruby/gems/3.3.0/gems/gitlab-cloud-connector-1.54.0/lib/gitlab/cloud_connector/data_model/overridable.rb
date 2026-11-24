# frozen_string_literal: true

module Gitlab
  module CloudConnector
    module DataModel
      module Overridable
        OverrideLoadError = Class.new(StandardError)

        def apply_overrides(base_data, model_class)
          overrides = fetch_relevant_overrides(base_data, model_class)
          return base_data unless overrides

          base_data.merge(overrides)
        end

        private

        def fetch_relevant_overrides(base_data, model_class)
          data = load_override_data
          return unless data

          model_name = base_data[:name]&.to_sym
          return unless model_name

          model_type = model_class.model_name.tableize.to_sym
          data.dig(model_type, model_name)
        end

        def load_override_data
          config = Gitlab::CloudConnector::Configuration.override_config

          data = config.respond_to?(:call) ? config.call : config
          unless data.is_a?(Hash) || data.nil?
            raise OverrideLoadError, "Invalid override config type: #{data.class}. Expected Hash or nil."
          end

          data
        rescue StandardError => e
          raise e if e.is_a?(OverrideLoadError)

          raise OverrideLoadError, "Failed to load override config: #{e.class}: #{e.message}"
        end
      end
    end
  end
end
