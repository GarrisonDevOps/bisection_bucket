# frozen_string_literal: true

module API
  module Entities
    class MobilePushSubscription < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the subscription.' }
      expose :created_at,
        documentation: { type: 'DateTime', example: '2026-07-30T12:00:00.000Z',
                         desc: 'Date and time when the subscription was created.' }
    end
  end
end
