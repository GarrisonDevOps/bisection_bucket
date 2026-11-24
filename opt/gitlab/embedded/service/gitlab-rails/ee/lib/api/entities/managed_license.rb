# frozen_string_literal: true

module API
  module Entities
    class ManagedLicense < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64' }
      expose :name, documentation: { type: 'String' }
      expose :approval_status, documentation: { type: 'String' }
    end
  end
end
