# frozen_string_literal: true

module API
  module Entities
    class AccessRequester < Grape::Entity
      expose :user, merge: true, using: ::API::Entities::UserBasic,
        documentation: { type: 'API::Entities::UserBasic' }
      expose :requested_at, documentation: { type: 'DateTime', example: '2025-01-01T00:00:00.000Z' }
    end
  end
end
