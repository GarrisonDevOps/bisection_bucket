# frozen_string_literal: true

module API
  module Entities
    class GroupPushRule < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 2, desc: 'ID of the push rule.' }
      expose :created_at, documentation: {
        type: 'DateTime', example: '2020-08-31T15:53:00.073Z',
        desc: 'Date and time when the push rule was created.'
      }
      expose :commit_message_regex, documentation: {
        type: 'String', example: '[a-zA-Z]',
        desc: 'Allow only commit messages that match this regular expression.'
      }
      expose :commit_message_negative_regex, documentation: {
        type: 'String', example: '[x+]',
        desc: 'Reject commit messages matching this regular expression.'
      }
      expose :branch_name_regex, documentation: {
        type: 'String', example: '[a-z]',
        desc: 'Allow only branch names that match this regular expression.'
      }
      expose :author_email_regex, documentation: {
        type: 'String', example: '^[A-Za-z0-9.]+@gitlab.com$',
        desc: 'Allow only commit author emails that match this regular expression.'
      }
      expose :file_name_regex, documentation: {
        type: 'String', example: '(exe)$',
        desc: 'Reject filenames matching this regular expression.'
      }
      expose :deny_delete_tag, documentation: { type: 'Boolean', desc: 'If `true`, denies deleting a tag.' }
      expose :member_check, documentation: {
        type: 'Boolean', example: true,
        desc: 'If `true`, allows only GitLab users to author commits.'
      }
      expose :prevent_secrets, documentation: {
        type: 'Boolean',
        desc: 'If `true`, rejects files that are likely to contain secrets.'
      }
      expose :max_file_size, documentation: { type: 'Integer', example: 100, desc: 'Maximum file size (MB) allowed.' }
      expose :commit_committer_check,
        if: ->(push_rule) { push_rule.available?(:commit_committer_check) },
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, allows commits from users only if the committer email is one of their own verified emails.'
        }
      expose :commit_committer_name_check,
        if: ->(push_rule) { push_rule.available?(:commit_committer_name_check) },
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, allows commits from users only if the commit author name is consistent with their ' \
            'GitLab account name.'
        }
      expose :reject_unsigned_commits,
        if: ->(push_rule) { push_rule.available?(:reject_unsigned_commits) },
        documentation: { type: 'Boolean', desc: 'If `true`, rejects a commit when it is not signed.' }
      expose :reject_non_dco_commits,
        if: ->(push_rule) { push_rule.available?(:reject_non_dco_commits) },
        documentation: { type: 'Boolean', desc: 'If `true`, rejects a commit when it is not DCO certified.' }
    end
  end
end
