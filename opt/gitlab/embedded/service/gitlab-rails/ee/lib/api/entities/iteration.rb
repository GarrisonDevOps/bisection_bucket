# frozen_string_literal: true

module API
  module Entities
    class Iteration < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :iid, documentation: { type: 'Integer', example: 1 }
      expose :sequence, documentation: { type: 'Integer', example: 1 }
      expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :title, documentation: { type: 'String', example: 'Iteration I' }
      expose :description, documentation: { type: 'String', example: 'Iteration description' }
      expose :state_enum, as: :state, documentation: { type: 'Integer', example: 1 }
      expose :created_at, documentation: { type: 'DateTime', example: '2022-01-31T15:10:45.080Z' }
      expose :updated_at, documentation: { type: 'DateTime', example: '2022-01-31T15:10:45.080Z' }
      expose :start_date, documentation: { type: 'Date', example: '2022-01-01' }
      expose :due_date, documentation: { type: 'Date', example: '2022-01-31' }

      expose :web_url,
        documentation: {
          type: 'String',
          example: 'https://gitlab.example.com/groups/gitlab-org/-/iterations/1'
        } do |iteration, _options|
        Gitlab::UrlBuilder.build(iteration)
      end
    end
  end
end
