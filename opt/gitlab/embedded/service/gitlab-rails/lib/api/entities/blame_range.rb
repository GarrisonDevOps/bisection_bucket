# frozen_string_literal: true

module API
  module Entities
    class BlameRange < Grape::Entity
      expose :commit, using: ::API::Entities::BlameRangeCommit,
        documentation: { type: '::API::Entities::BlameRangeCommit',
                         desc: 'Commit that last changed the lines in this blame range.' }
      expose :lines,
        documentation: { type: 'String', is_array: true, example: ['lorem ipsum'],
                         desc: 'Lines of the file in this blame range.' }
    end
  end
end
