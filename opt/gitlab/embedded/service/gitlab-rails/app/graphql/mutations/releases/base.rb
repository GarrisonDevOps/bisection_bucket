# frozen_string_literal: true

module Mutations
  module Releases
    class Base < BaseMutation
      include FindsProject

      RELEASE_WRITES_LIMIT_DESCRIPTION = 'Release creates and updates are rate limited per project ' \
        '(`release_writes_limit_per_project` application setting) and per user (`release_writes_limit_per_user` ' \
        'application setting). Requests over a limit are blocked when its feature flag ' \
        '(`rate_limit_release_writes_per_project` or `rate_limit_release_writes_per_user`) is enabled, and only ' \
        'logged otherwise.'

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: 'Full path of the project the release is associated with.'
    end
  end
end
