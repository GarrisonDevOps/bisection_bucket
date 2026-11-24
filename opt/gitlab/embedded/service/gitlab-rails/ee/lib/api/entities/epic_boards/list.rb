# frozen_string_literal: true

module API
  module Entities
    module EpicBoards
      class List < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        expose :label, using: ::API::Entities::LabelBasic
        expose :position, documentation: { type: 'Integer', example: 1 }
        expose :list_type, documentation: { type: 'String', example: 'backlog' }
      end
    end
  end
end
