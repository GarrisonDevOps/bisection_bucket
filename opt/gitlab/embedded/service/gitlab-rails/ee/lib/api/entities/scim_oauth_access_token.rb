# frozen_string_literal: true

module API
  module Entities
    class ScimOauthAccessToken < ScimAccessTokenBase
      expose :organization_id, documentation: { type: 'Integer', format: 'int64', example: 1 }

      # DEPRECATED: group tokens moved to `GroupScimAuthAccessToken`, so instance tokens have no
      # group. The key stays because REST API v4 cannot drop a response field.
      # To be removed with https://gitlab.com/gitlab-org/gitlab/-/issues/634483.
      expose :group_id, documentation: { type: 'Integer', format: 'int64', example: nil } do |_token|
        nil
      end
    end
  end
end
