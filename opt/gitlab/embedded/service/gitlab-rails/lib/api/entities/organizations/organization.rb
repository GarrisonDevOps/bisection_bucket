# frozen_string_literal: true

module API
  module Entities
    module Organizations
      class Organization < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the organization.' }
        expose :uuid, documentation: {
          type: 'String', example: '0192f8c2-1a2b-7cde-89ab-0123456789ab',
          desc: 'UUID of the organization.'
        }
        expose :name, documentation: { type: 'String', example: 'GitLab', desc: 'Name of the organization.' }
        expose :path, documentation: { type: 'String', example: 'gitlab', desc: 'Path of the organization.' }
        expose :description, documentation: {
          type: 'String', example: 'My description',
          desc: 'Description of the organization.'
        }
        expose :visibility, documentation: {
          type: 'String', example: 'public',
          desc: 'Visibility level of the organization.'
        }
        expose :created_at, documentation: {
          type: 'DateTime', example: '2022-02-24T20:22:30.097Z',
          desc: 'Date and time when the organization was created.'
        }
        expose :updated_at, documentation: {
          type: 'DateTime', example: '2022-02-24T20:22:30.097Z',
          desc: 'Date and time when the organization was last updated.'
        }
        expose :web_url, documentation: {
          type: 'String', example: "https://example.com/o/gitlab/-/overview",
          desc: 'Web URL of the organization.'
        }
        expose(:avatar_url, documentation: {
          type: 'String',
          example: 'https://example.com/uploads/-/system/organizations/organization_detail/avatar/1/avatar.png',
          desc: 'URL of the organization avatar.'
        }) do |organization, _options|
          organization.avatar_url(only_path: false)
        end
      end
    end
  end
end
