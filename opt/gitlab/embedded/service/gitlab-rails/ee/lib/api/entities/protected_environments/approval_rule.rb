# frozen_string_literal: true

module API
  module Entities
    module ProtectedEnvironments
      class ApprovalRule < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64' }
        expose :user_id, documentation: { type: 'Integer', format: 'int64' }
        expose :group_id, documentation: { type: 'Integer', format: 'int64' }
        # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
        expose :access_level, documentation: { type: 'Integer' }
        # rubocop:enable API/AccessLevelStringType
        expose :humanize, as: :access_level_description, documentation: { type: 'String' }
        expose :required_approvals, documentation: { type: 'Integer' }
        expose :group_inheritance_type, documentation: { type: 'Integer' }
      end
    end
  end
end
