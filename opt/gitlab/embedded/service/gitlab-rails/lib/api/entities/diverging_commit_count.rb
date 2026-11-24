# frozen_string_literal: true

module API
  module Entities
    class DivergingCommitCount < Grape::Entity
      expose :behind, documentation: {
        type: 'Integer', example: 3, desc: 'Number of commits in `from` that are not in `to`.'
      }
      expose :ahead, documentation: {
        type: 'Integer', example: 5, desc: 'Number of commits in `to` that are not in `from`.'
      }
    end
  end
end
