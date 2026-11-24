# frozen_string_literal: true

module API
  module Orbit
    module McpHandlers
      # See: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/ping
      class Ping < Base
        def invoke
          {}
        end
      end
    end
  end
end
