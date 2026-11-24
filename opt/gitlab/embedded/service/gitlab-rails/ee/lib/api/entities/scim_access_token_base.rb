# frozen_string_literal: true

module API
  module Entities
    class ScimAccessTokenBase < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :created_at, documentation: { type: 'DateTime', example: '2024-01-01T12:00:00.000Z' }
    end
  end
end
