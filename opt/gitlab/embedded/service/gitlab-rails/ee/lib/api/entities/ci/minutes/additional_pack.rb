# frozen_string_literal: true

module API
  module Entities
    module Ci
      module Minutes
        class AdditionalPack < Grape::Entity
          expose :namespace_id, documentation: { type: 'Integer', format: 'int64', example: 123 }
          expose :expires_at, documentation: { type: 'Date', example: '2012-05-28' }
          expose :number_of_minutes, documentation: { type: 'Integer', example: 10000 }
          expose :purchase_xid, documentation: { type: 'String', example: '46952fe69bebc1a4de10b2b4ff439d0c' }
        end
      end
    end
  end
end
