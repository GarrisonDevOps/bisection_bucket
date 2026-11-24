# frozen_string_literal: true

module Gitlab
  module Insights
    module Validators
      class ConfigValidator
        def initialize(config)
          @config = config
        end

        def valid?
          config.is_a?(Hash) && config.values.all?(Hash)
        end

        def valid_entries
          return {} unless config.is_a?(Hash)

          config.select { |_, entry| renderable?(entry) }
        end

        def invalid_entries
          return {} unless config.is_a?(Hash)

          config.reject { |_, entry| renderable?(entry) }
        end

        private

        attr_reader :config

        def renderable?(entry)
          entry.is_a?(Hash) && (entry[:title] || entry[:charts])
        end
      end
    end
  end
end
