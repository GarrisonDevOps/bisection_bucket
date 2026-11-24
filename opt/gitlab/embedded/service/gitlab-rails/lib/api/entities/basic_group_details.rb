# frozen_string_literal: true

module API
  module Entities
    class BasicGroupDetails < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', desc: 'ID of the group.' }
      expose :web_url,
        documentation: { type: 'String', example: 'http://gitlab.example.com/groups/diaspora',
                         desc: 'URL to access the group in a browser.' }
      expose :name, documentation: { type: 'String', example: 'Diaspora', desc: 'Name of the group.' }
    end
  end
end
