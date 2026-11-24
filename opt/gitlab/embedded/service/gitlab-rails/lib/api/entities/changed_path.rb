# frozen_string_literal: true

module API
  module Entities
    class ChangedPath < Grape::Entity
      expose :status, documentation: {
        type: 'String', example: 'MODIFIED',
        desc: 'Change type. One of `ADDED`, `MODIFIED`, `DELETED`, `RENAMED`, `TYPE_CHANGE`, or `COPIED`.'
      } do |changed_path|
        changed_path.status.to_s
      end
      expose :path, documentation: { type: 'String', example: 'app/models/user.rb', desc: 'Path of the file.' }
      expose :old_path, documentation: {
        type: 'String', example: 'app/models/user.rb',
        desc: 'Previous path of the file. Same as `path` unless the file was renamed or copied.'
      }
      expose :old_mode, documentation: { type: 'String', example: '100644', desc: 'Previous file mode.' }
      expose :new_mode, documentation: { type: 'String', example: '100644', desc: 'New file mode.' }
    end
  end
end
