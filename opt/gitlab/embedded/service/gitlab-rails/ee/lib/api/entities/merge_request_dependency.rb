# frozen_string_literal: true

module API
  module Entities
    class MergeRequestDependency < Grape::Entity
      include RequestAwareEntity

      expose :id, documentation: { type: 'Integer', format: 'int64', example: 123 }

      expose :blocking_merge_request, using: ::API::Entities::MergeRequestBasic, if: ->(block) {
        can?(options[:current_user], :read_merge_request, block.blocking_merge_request)
      }

      expose :blocked_merge_request, using: ::API::Entities::MergeRequestBasic, if: ->(blockee) {
        can?(options[:current_user], :read_merge_request, blockee.blocked_merge_request)
      }

      expose :project_id, documentation: { type: 'Integer', format: 'int64', example: 312 }
    end
  end
end
