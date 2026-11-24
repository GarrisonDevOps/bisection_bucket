# frozen_string_literal: true

module API
  module Entities
    class DiffStat < Grape::Entity
      expose :path, documentation: { type: 'String', example: 'app/models/user.rb', desc: 'Path of the file.' }
      expose :old_path, documentation: {
        type: 'String', example: 'app/models/user.rb',
        desc: 'Previous path of the file. Differs from `path` when the file was renamed.'
      }
      expose :additions, documentation: { type: 'Integer', example: 10, desc: 'Number of added lines.' }
      expose :deletions, documentation: { type: 'Integer', example: 3, desc: 'Number of deleted lines.' }
    end
  end
end
