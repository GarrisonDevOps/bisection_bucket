# frozen_string_literal: true

module API
  module Entities
    module Ci
      module Minutes
        class Usage < Grape::Entity
          expose :total_minutes_used, documentation: {
            type: 'Integer', example: 105, desc: 'Total compute minutes used in the current billing period.'
          }
          expose :monthly_minutes_used, documentation: {
            type: 'Integer', example: 100, desc: 'Compute minutes used from the monthly quota.'
          }
          expose :purchased_minutes_used, documentation: {
            type: 'Integer', example: 5, desc: 'Compute minutes used from additional purchased allocations.'
          }
        end
      end
    end
  end
end
