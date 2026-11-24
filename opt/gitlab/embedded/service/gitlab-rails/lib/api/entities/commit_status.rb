# frozen_string_literal: true

module API
  module Entities
    class CommitStatus < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 93, desc: 'ID of the status.' }
      expose :sha, documentation: {
        type: 'String', example: '18f3e63d05582537db6d183d9d557be09e1f90c8', desc: 'SHA of the commit.'
      }
      expose :ref, documentation: { type: 'String', example: 'develop', desc: 'Branch or tag of the commit.' }
      expose :status, documentation: { type: 'String', example: 'success', desc: 'Status of the commit.' }
      expose :name, documentation: { type: 'String', example: 'default', desc: 'Name of the status.' }
      expose :target_url, documentation: {
        type: 'String',
        example: 'https://gitlab.example.com/janedoe/gitlab-foss/builds/91',
        desc: 'Target URL associated with the status.'
      }
      expose :description, documentation: { type: 'String', desc: 'Description of the status.' }
      expose :created_at, documentation: {
        type: 'DateTime', example: '2016-01-19T09:05:50.355Z', desc: 'Date and time when the status was created.'
      }
      expose :started_at, documentation: {
        type: 'DateTime', example: '2016-01-20T08:40:25.832Z', desc: 'Date and time when the status started.'
      }
      expose :finished_at, documentation: {
        type: 'DateTime', example: '2016-01-21T08:40:25.832Z', desc: 'Date and time when the status finished.'
      }
      expose :allow_failure, documentation: {
        type: 'Boolean', example: false, desc: 'If `true`, the status is allowed to fail.'
      }
      expose :coverage, documentation: {
        type: 'Float', format: 'float', example: 98.29, desc: 'Code coverage percentage.'
      }
      expose :pipeline_id, documentation: { type: 'Integer', format: 'int64', example: 101 }

      expose :author, using: ::API::Entities::UserBasic, documentation: {
        type: '::API::Entities::UserBasic', desc: 'User who created the status.'
      }
    end
  end
end
