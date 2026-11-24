# frozen_string_literal: true

module API
  module Entities
    class Discussion < Grape::Entity
      expose :id, documentation: {
        type: 'String', example: '6a9c1750b37d513a43987b574953fceb50b03ce7', desc: 'ID of the discussion.'
      }
      expose :individual_note?, as: :individual_note, documentation: {
        type: 'Boolean', example: false, desc: 'If `true`, the discussion is a single note and not a thread.'
      }
      expose :resolvable?, as: :resolvable, documentation: { type: 'Boolean' }
      expose :resolved?, as: :resolved, documentation: { type: 'Boolean' }, if: ->(d, _) { d.resolvable? }
      expose :notes, using: ::API::Entities::Note, documentation: {
        type: '::API::Entities::Note', is_array: true, desc: 'Notes in the discussion.'
      }
    end
  end
end
