# frozen_string_literal: true

module API
  module Entities
    class UserCreditCardValidations < Grape::Entity
      expose :user_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :credit_card_validated_at, documentation: { type: 'DateTime', example: '2025-01-01T00:00:00.000Z' }
    end
  end
end
