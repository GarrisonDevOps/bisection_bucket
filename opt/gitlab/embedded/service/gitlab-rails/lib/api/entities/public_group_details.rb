# frozen_string_literal: true

module API
  module Entities
    class PublicGroupDetails < BasicGroupDetails
      expose :avatar_url,
        documentation: { type: 'String',
                         example: 'http://gitlab.example.com/uploads/group/avatar/1/avatar.png',
                         desc: "URL of the group's avatar image." } do |group, options|
        group.avatar_url(only_path: false)
      end
      expose :full_name, documentation: { type: 'String', example: 'Foobar Group', desc: 'Full name of the group.' }
      expose :full_path, documentation: { type: 'String', example: 'foo-bar', desc: 'Full path of the group.' }
    end
  end
end
