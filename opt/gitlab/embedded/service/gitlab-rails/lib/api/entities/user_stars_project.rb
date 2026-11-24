# frozen_string_literal: true

module API
  module Entities
    class UserStarsProject < Grape::Entity
      expose :starred_since, documentation: { type: 'DateTime', example: '2025-01-01T00:00:00.000Z' }
      expose :user, using: ::API::Entities::UserBasic,
        documentation: { type: 'API::Entities::UserBasic' }
    end
  end
end
