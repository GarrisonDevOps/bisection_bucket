# frozen_string_literal: true

module API
  module Entities
    module Deployments
      class Approval < Grape::Entity
        expose :user, using: ::API::Entities::UserBasic
        expose :status, documentation: { type: 'String', example: 'approved' }
        expose :created_at, documentation: { type: 'DateTime', example: '2022-02-24T20:22:30.097Z' }
        expose :comment, documentation: { type: 'String', example: 'LGTM' }
      end
    end
  end
end
