# frozen_string_literal: true

module API
  module Entities
    class EpicBoard < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :name, documentation: { type: 'String', example: 'Team Board' }
      expose :hide_backlog_list, documentation: { type: 'Boolean', example: false }
      expose :hide_closed_list, documentation: { type: 'Boolean', example: true }
      expose :group, using: ::API::Entities::BasicGroupDetails
      expose :labels, using: ::API::Entities::LabelBasic, documentation: { is_array: true }
      expose :lists, using: ::API::Entities::EpicBoards::List, documentation: { is_array: true }
    end
  end
end
