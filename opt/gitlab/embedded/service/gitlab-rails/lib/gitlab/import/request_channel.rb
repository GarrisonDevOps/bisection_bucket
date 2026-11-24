# frozen_string_literal: true

module Gitlab
  module Import
    # Detects how an import/migration was initiated, for the `request_channel`
    # internal event property (API vs. UI vs. Congregate). Congregate is a
    # Professional Services migration tool that itself calls the API; it is
    # identified by its User-Agent.
    #
    # Callers pass an explicit :ui from web controllers; API endpoints call
    # `.detect(request)` to distinguish plain API from Congregate.
    module RequestChannel
      API = :api
      UI = :ui
      CONGREGATE = :congregate

      # "GitLabApiClient" (older Congregate versions) will no longer be supported with
      # https://gitlab.com/gitlab-org/gitlab/-/issues/638427
      CONGREGATE_USER_AGENT_PATTERN = /\A(?:GitLabCongregate|GitLabApiClient)\b/

      REQUEST_STORE_KEY = :import_request_channel

      def self.detect(request)
        return CONGREGATE if congregate?(request)

        API
      end

      def self.congregate?(request)
        user_agent = request&.user_agent
        return false if user_agent.blank?

        CONGREGATE_USER_AGENT_PATTERN.match?(user_agent)
      end

      # Hands the channel from Import::BaseService to ProjectImportState#after_create
      # within the same request, since Rails autosave creates the import state.
      def self.stash(value)
        Gitlab::SafeRequestStore[REQUEST_STORE_KEY] = value
      end

      def self.stashed
        Gitlab::SafeRequestStore[REQUEST_STORE_KEY]
      end
    end
  end
end
