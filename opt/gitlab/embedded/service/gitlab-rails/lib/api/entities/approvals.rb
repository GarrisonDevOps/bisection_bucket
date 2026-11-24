# frozen_string_literal: true

module API
  module Entities
    class Approvals < Grape::Entity
      expose :user, using: ::API::Entities::UserBasic,
        documentation: { type: '::API::Entities::UserBasic', desc: 'User who approved the merge request.' }
      expose :created_at, as: :approved_at, documentation: {
        type: 'DateTime', example: '2025-01-01T10:00:00Z',
        desc: 'Timestamp of when the user approved the merge request.'
      }
    end
  end
end
