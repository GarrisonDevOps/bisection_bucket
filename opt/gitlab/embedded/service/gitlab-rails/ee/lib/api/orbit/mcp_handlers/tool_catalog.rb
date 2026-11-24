# frozen_string_literal: true

module API
  module Orbit
    module McpHandlers
      module ToolCatalog
        COMMAND_TOOL_NAMES = %w[list_commands invoke_command].freeze

        def self.trusted_tool?(name)
          COMMAND_TOOL_NAMES.include?(name)
        end
      end
    end
  end
end
