# frozen_string_literal: true

module API
  module Entities
    class BasicSnippet < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the snippet.' }
      expose :title, documentation: { type: 'String', example: 'test', desc: 'Title of the snippet.' }
      expose :description,
        documentation: { type: 'String', example: 'Ruby test snippet', desc: 'Description of the snippet.' }
      expose :visibility, documentation: { type: 'String', example: 'public', desc: 'Visibility level of the snippet.' }
      expose :author, using: ::API::Entities::UserBasic,
        documentation: { type: '::API::Entities::UserBasic', desc: 'Author of the snippet.' }
      expose :created_at,
        documentation: { type: 'DateTime', example: '2012-06-28T10:52:04Z',
                         desc: 'Date and time when the snippet was created.' }
      expose :updated_at,
        documentation: { type: 'DateTime', example: '2012-06-28T10:52:04Z',
                         desc: 'Date and time when the snippet was last updated.' }
      expose :project_id,
        documentation: { type: 'Integer', format: 'int64', example: 1,
                         desc: 'ID of the project the snippet belongs to. `null` for personal snippets.' }
      expose :web_url, documentation: {
        type: 'String', example: 'http://example.com/example/example/snippets/1',
        desc: 'URL to the snippet in the GitLab UI.'
      } do |snippet|
        Gitlab::UrlBuilder.build(snippet)
      end
      expose :raw_url, documentation: {
        type: 'String', example: 'http://example.com/example/example/snippets/1/raw',
        desc: 'URL to the raw snippet content.'
      } do |snippet|
        Gitlab::UrlBuilder.build(snippet, raw: true)
      end
      expose :ssh_url_to_repo, documentation: {
        type: 'String', example: 'ssh://user@gitlab.example.com/snippets/65.git',
        desc: 'SSH URL to the snippet repository. Returned only if the snippet repository exists.'
      }, if: ->(snippet) { snippet.repository_exists? }
      expose :http_url_to_repo, documentation: {
        type: 'String', example: 'https://gitlab.example.com/snippets/65.git',
        desc: 'HTTP URL to the snippet repository. Returned only if the snippet repository exists.'
      }, if: ->(snippet) { snippet.repository_exists? }
    end
  end
end
