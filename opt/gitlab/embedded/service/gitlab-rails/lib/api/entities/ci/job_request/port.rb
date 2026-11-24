# frozen_string_literal: true

module API
  module Entities
    module Ci
      module JobRequest
        class Port < Grape::Entity
          expose :number, documentation: { type: 'Integer' }
          expose :protocol, documentation: { type: 'String' }
          expose :name, documentation: { type: 'String' }
        end
      end
    end
  end
end
