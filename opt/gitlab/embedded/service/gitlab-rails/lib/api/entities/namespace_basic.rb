# frozen_string_literal: true

module API
  module Entities
    class NamespaceBasic < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 2, desc: 'ID of the namespace.' }
      expose :name, documentation: { type: 'String', example: 'project', desc: 'Name of the namespace.' }
      expose :path, documentation: { type: 'String', example: 'my_project', desc: 'Path of the namespace.' }
      expose :kind,
        documentation: { type: 'String', example: 'project',
                         desc: 'Type of the namespace: `user`, `group`, or `project`.' }
      expose :full_path,
        documentation: { type: 'String', example: 'group/my_project',
                         desc: 'Full path of the namespace, including the paths of its parent groups.' }
      expose :parent_id,
        documentation: { type: 'Integer', format: 'int64', example: 1,
                         desc: 'ID of the parent namespace. `null` for top-level namespaces.' }
      expose :avatar_url,
        documentation: { type: 'String', example: 'https://example.com/avatar/12345',
                         desc: 'URL of the namespace avatar. For a group, `null` if no avatar is set.' }

      expose :web_url, documentation: {
        type: 'String', example: 'https://example.com/group/my_project',
        desc: 'Web URL of the namespace. For a user namespace, the URL of the user profile.'
      } do |namespace|
        if namespace.user_namespace?
          Gitlab::Routing.url_helpers.user_url(namespace.owner || namespace.route.path)
        else
          namespace.web_url
        end
      end
    end
  end
end
