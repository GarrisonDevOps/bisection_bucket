# frozen_string_literal: true

module Types
  class PushRulesType < BaseObject
    graphql_name 'PushRules'
    description 'Represents rules that commit pushes must follow.'
    accepts ::PushRule

    authorize :read_project
    authorize_granular_token permissions: :read_push_rule, boundary: :project, boundary_type: :project

    field :deny_delete_tag,
      GraphQL::Types::Boolean,
      null: true,
      description: 'Deny deleting a tag with `git push`.'

    field :member_check,
      GraphQL::Types::Boolean,
      null: true,
      description: 'Restrict commits by author (email) to existing GitLab users.'

    field :prevent_secrets,
      GraphQL::Types::Boolean,
      null: true,
      description: 'GitLab rejects any files that are likely to contain secrets.'

    # rubocop:disable GraphQL/ExtractType -- These fields match the REST API structure and PushRule model
    field :commit_message_regex,
      GraphQL::Types::String,
      null: true,
      description: 'All commit messages must match the regular expression.'

    field :commit_message_negative_regex,
      GraphQL::Types::String,
      null: true,
      description: 'No commit message is allowed to match the regular expression.'
    # rubocop:enable GraphQL/ExtractType

    field :branch_name_regex,
      GraphQL::Types::String,
      null: true,
      description: 'All branch names must match the regular expression.'

    field :author_email_regex,
      GraphQL::Types::String,
      null: true,
      description: 'All commit author emails must match the regular expression.'

    field :file_name_regex,
      GraphQL::Types::String,
      null: true,
      description: 'All committed filenames must not match the regular expression.'

    field :max_file_size,
      GraphQL::Types::Int,
      null: true,
      description: 'Maximum file size (MB).'

    # rubocop:disable GraphQL/ExtractType -- These fields match the REST API structure and PushRule model
    field :commit_committer_check,
      GraphQL::Types::Boolean,
      null: false,
      description: 'Only allow commits where the committer email matches a verified GitLab user email.'

    field :commit_committer_name_check,
      GraphQL::Types::Boolean,
      null: false,
      description: 'Only allow commits where the author name matches the GitLab user name.'
    # rubocop:enable GraphQL/ExtractType

    # rubocop:disable GraphQL/ExtractType -- These fields match the REST API structure and PushRule model
    field :reject_unsigned_commits,
      GraphQL::Types::Boolean,
      null: false,
      description: 'Reject commit when it is not signed through GPG.'

    field :reject_non_dco_commits,
      GraphQL::Types::Boolean,
      null: false,
      description: 'Reject commit when it is not DCO certified.'
    # rubocop:enable GraphQL/ExtractType

    def commit_committer_check
      !!(object.available?(:commit_committer_check) && object.commit_committer_check)
    end

    def commit_committer_name_check
      !!(object.available?(:commit_committer_name_check) && object.commit_committer_name_check)
    end

    def reject_unsigned_commits
      !!(object.available?(:reject_unsigned_commits) && object.reject_unsigned_commits)
    end

    def reject_non_dco_commits
      !!(object.available?(:reject_non_dco_commits) && object.reject_non_dco_commits)
    end
  end
end
