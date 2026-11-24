# frozen_string_literal: true

module API
  module Entities
    class Commit < Grape::Entity
      expose :id, documentation: {
        type: 'String', example: '2695effb5807a22ff3d138d593fd856244e155e7', desc: 'Full SHA of the commit.'
      }
      expose :short_id, documentation: { type: 'String', example: '2695effb', desc: 'Short SHA of the commit.' }
      expose :created_at, documentation: {
        type: 'DateTime', example: '2017-07-26T11:08:53.000+02:00',
        desc: 'Date and time when the commit was created. Identical to `committed_date`.'
      }
      expose :parent_ids,
        documentation: {
          type: 'String', is_array: true, example: ['2a4b78934375d7f53875269ffd4f45fd83a84ebe'],
          desc: 'SHAs of the parent commits.'
        }
      expose :full_title, as: :title, documentation: {
        type: 'String', example: 'Initial commit', desc: 'Title of the commit message.'
      }
      expose :safe_message, as: :message, documentation: {
        type: 'String', example: 'Initial commit', desc: 'Full commit message.'
      }
      expose :author_name, documentation: { type: 'String', example: 'John Smith', desc: 'Name of the commit author.' }
      expose :author_email, documentation: {
        type: 'String', example: 'john@example.com', desc: 'Email address of the commit author.'
      }
      expose :authored_date, documentation: {
        type: 'DateTime', example: '2012-05-28T04:42:42-07:00', desc: 'Date and time when the commit was authored.'
      }
      expose :committer_name, documentation: { type: 'String', example: 'Jack Smith', desc: 'Name of the committer.' }
      expose :committer_email, documentation: {
        type: 'String', example: 'jack@example.com', desc: 'Email address of the committer.'
      }
      expose :committed_date, documentation: {
        type: 'DateTime', example: '2012-05-28T04:42:42-07:00', desc: 'Date and time when the commit was committed.'
      }
      expose :trailers, documentation: {
        type: 'Hash', example: { "Merged-By" => "Jane Doe janedoe@gitlab.com" },
        desc: 'Git trailers parsed from the commit message. Duplicate keys include the last value only.'
      }
      expose :extended_trailers, documentation: {
        type: 'Hash',
        example: { "Signed-off-by" => ["John Doe <johndoe@gitlab.com>", "Jane Doe <janedoe@gitlab.com>"] },
        desc: 'Git trailers parsed from the commit message, with every value for each key.'
      }

      expose :web_url,
        documentation: {
          type: 'String',
          example: 'https://gitlab.example.com/janedoe/gitlab-foss/-/commit/ed899a2f4b50b4370feeea94676502b42383c746',
          desc: 'URL to view the commit in the GitLab UI.'
        } do |commit, _options|
        c = commit
        c = c.__subject__ if c.is_a?(Gitlab::View::Presenter::Base)
        Gitlab::UrlBuilder.build(c)
      end
    end
  end
end
