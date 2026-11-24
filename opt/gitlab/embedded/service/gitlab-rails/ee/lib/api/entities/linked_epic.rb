# frozen_string_literal: true

module API
  module Entities
    class LinkedEpic < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :iid, documentation: { type: 'Integer', example: 1 }
      expose :title, documentation: { type: 'String', example: 'Linked epic' }
      expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :parent_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :has_children?, as: :has_children, documentation: { type: 'Boolean', example: false }
      expose :has_issues?, as: :has_issues, documentation: { type: 'Boolean', example: false }
      expose :reference, documentation: { type: 'String', example: '&1' } do |epic|
        epic.to_reference(epic.parent.group)
      end

      expose :url,
        documentation: { type: 'String', example: 'https://gitlab.example.com/groups/gitlab-org/-/epics/1' } do |epic|
        ::Gitlab::Routing.url_helpers.group_epic_url(epic.group, epic)
      end

      expose :relation_url,
        documentation: { type: 'String',
                         example: 'https://gitlab.example.com/groups/gitlab-org/-/epics/1/links/1' } do |epic|
        # The URL pointed to an internal controller endpoint.
        # We no longer have the EpicLinksController or routes, so we need to build the URL statically
        # to not break the REST API.
        "#{::Gitlab::Routing.url_helpers.group_epic_url(epic.parent.group, epic.parent)}/links/#{epic.id}"
      end
    end
  end
end
