# frozen_string_literal: true

module API
  module Entities
    module Ci
      module JobRouter
        class DiscoveryInformation < Grape::Entity
          expose :server_url,
            documentation: { type: 'String', example: 'wss://kas.example.com', desc: 'URL of the Job Router.' }
        end
      end
    end
  end
end
