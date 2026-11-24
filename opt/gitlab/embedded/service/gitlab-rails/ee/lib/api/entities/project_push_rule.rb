# frozen_string_literal: true

module API
  module Entities
    class ProjectPushRule < Grape::Entity
      extend ::API::Entities::EntityHelpers

      expose :id, documentation: { type: 'Integer', format: 'int64', example: 2, desc: 'ID of the push rule.' }
      expose :project_id, documentation: { type: 'Integer', format: 'int64', example: 3, desc: 'ID of the project.' }
      expose :created_at, documentation: {
        type: 'DateTime', example: '2020-08-31T15:53:00.073Z',
        desc: 'Date and time when the push rule was created.'
      }
      expose :commit_message_regex, documentation: {
        type: 'String', example: 'Fixed \d+\..*',
        desc: 'All commit messages must match this regular expression.'
      }
      expose :commit_message_negative_regex, documentation: {
        type: 'String', example: 'ssh\:\/\/',
        desc: 'No commit message is allowed to match this regular expression.'
      }
      expose :branch_name_regex, documentation: {
        type: 'String', example: '(feature|hotfix)\/.*',
        desc: 'All branch names must match this regular expression.'
      }
      expose :deny_delete_tag, documentation: {
        type: 'Boolean', example: true,
        desc: 'If `true`, denies deleting a tag.'
      }
      expose :member_check, documentation: {
        type: 'Boolean', example: true,
        desc: 'If `true`, restricts commits by author (email) to existing GitLab users.'
      }
      expose :prevent_secrets, documentation: {
        type: 'Boolean', example: true,
        desc: 'If `true`, GitLab rejects any files that are likely to contain secrets.'
      }
      expose :author_email_regex, documentation: {
        type: 'String', example: '@my-company.com$',
        desc: 'All commit author emails must match this regular expression.'
      }
      expose :file_name_regex, documentation: {
        type: 'String', example: '(jar|exe)$',
        desc: 'All committed filenames must not match this regular expression.'
      }
      expose :max_file_size, documentation: { type: 'Integer', example: 1024, desc: 'Maximum file size (MB).' }
      expose_restricted :commit_committer_check, documentation: {
        type: 'Boolean', example: true,
        desc: 'If `true`, users can only push commits to this repository if the committer email is one of their ' \
          'own verified emails.'
      }, &:project
      expose_restricted :commit_committer_name_check, documentation: {
        type: 'Boolean', example: true,
        desc: 'If `true`, users can only push commits to this repository if the commit author name is consistent ' \
          'with their GitLab account name.'
      }, &:project
      expose_restricted :reject_unsigned_commits, documentation: {
        type: 'Boolean', example: true,
        desc: 'If `true`, rejects commits when not signed.'
      }, &:project
      expose_restricted :reject_non_dco_commits, documentation: {
        type: 'Boolean', example: true,
        desc: 'If `true`, rejects commits when not DCO certified.'
      }, &:project
    end
  end
end
