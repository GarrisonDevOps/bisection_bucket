# frozen_string_literal: true

module Ai
  module Catalog
    module Concerns
      module FlowDefinitionToolExtractor
        extend ActiveSupport::Concern

        private

        # @return [Array] tool names extracted from flow definition
        def extract_tools_from_flow_definition(definition)
          return [] unless definition

          Array(definition['components']).flat_map do |component|
            tool_names = Array(component['toolset']).map do |entry|
              entry.is_a?(Hash) ? entry.each_key.first : entry
            end

            tool_names << component['tool_name'] if component['tool_name']

            tool_names
          end.compact
        end
      end
    end
  end
end
