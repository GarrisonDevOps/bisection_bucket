# frozen_string_literal: true

module API
  module Entities
    class Email < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :email, documentation: { type: 'String', example: 'user@example.com' }
      expose :confirmed_at, documentation: { type: 'DateTime', example: '2015-12-24T15:51:21.880Z' }
    end
  end
end
