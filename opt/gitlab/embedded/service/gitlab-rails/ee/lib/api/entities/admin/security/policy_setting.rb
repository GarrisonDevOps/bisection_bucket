# frozen_string_literal: true

module API
  module Entities
    module Admin
      module Security
        class PolicySetting < Grape::Entity
          expose :csp_namespace_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        end
      end
    end
  end
end
