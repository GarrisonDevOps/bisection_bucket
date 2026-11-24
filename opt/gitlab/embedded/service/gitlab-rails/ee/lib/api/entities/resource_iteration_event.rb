# frozen_string_literal: true

module API
  module Entities
    class ResourceIterationEvent < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 142 }
      expose :user, using: ::API::Entities::UserBasic
      expose :created_at, documentation: { type: 'DateTime', example: '2012-05-28T04:42:42-07:00' }
      expose :resource_type, documentation: { type: 'String', example: 'Issue' } do |event, _options|
        event.issuable.class.name
      end
      expose :resource_id, documentation: { type: 'Integer', format: 'int64', example: 253 } do |event, _options|
        event.issuable.id
      end
      expose :iteration, using: ::API::Entities::Iteration
      expose :action, documentation: { type: 'String', example: 'add' }
    end
  end
end
