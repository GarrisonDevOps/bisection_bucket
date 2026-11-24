# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        module Ci
          module Minutes
            class AdditionalPack < Grape::Entity
              expose :namespace_id, documentation: { type: 'String', example: '123' }
              expose :expires_at, documentation: { type: 'Date', example: '2012-05-28' }
              expose :number_of_minutes, documentation: { type: 'Integer', example: 10000 }
              expose :purchase_xid, documentation: { type: 'String', example: 'C-00123456' }
            end
          end
        end
      end
    end
  end
end
