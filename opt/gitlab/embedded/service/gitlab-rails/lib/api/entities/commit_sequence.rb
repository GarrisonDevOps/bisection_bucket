# frozen_string_literal: true

module API
  module Entities
    class CommitSequence < Grape::Entity
      expose :count, documentation: {
        type: 'Integer', example: 1,
        desc: 'Sequence number of the commit: the number of commits in its history, ' \
          'including itself.'
      }
    end
  end
end
