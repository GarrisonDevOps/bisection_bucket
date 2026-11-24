# frozen_string_literal: true

module API
  module Entities
    class ResourceWeightEvent < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 142 }
      expose :user, using: ::API::Entities::UserBasic
      expose :created_at, documentation: { type: 'DateTime', example: '2012-05-28T04:42:42-07:00' }
      expose :issue_id, documentation: { type: 'Integer', format: 'int64', example: 253 }
      expose :weight, documentation: { type: 'Integer', example: 3 }
    end
  end
end
