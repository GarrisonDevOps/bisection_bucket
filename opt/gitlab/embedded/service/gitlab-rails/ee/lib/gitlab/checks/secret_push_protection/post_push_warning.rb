# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class PostPushWarning < ::Gitlab::Checks::PostPushMessage
        MESSAGE_KEY_PREFIX = 'secret_push_protection:warning'

        attr_accessor :changed_paths_count, :changed_paths_threshold

        def self.message_key(user, repository)
          [
            MESSAGE_KEY_PREFIX,
            user&.id,
            repository&.project&.id
          ].compact.join(':')
        end

        def initialize(repository, user, protocol, changed_paths_count = nil, changed_paths_threshold = nil)
          super(repository, user, protocol)

          @changed_paths_count = changed_paths_count
          @changed_paths_threshold = changed_paths_threshold
        end

        def message
          return changed_paths_count_exceeded_message if changed_paths_count && changed_paths_threshold

          error_message
        end

        private

        def changed_paths_count_exceeded_message
          "Secret push protection was skipped: #{changed_paths_count} changed files exceeds " \
            "the threshold of #{changed_paths_threshold}. The push has been accepted."
        end

        def error_message
          'Secret push protection encountered an internal error and could not ' \
            'scan this push. The push has been accepted.'
        end
      end
    end
  end
end
