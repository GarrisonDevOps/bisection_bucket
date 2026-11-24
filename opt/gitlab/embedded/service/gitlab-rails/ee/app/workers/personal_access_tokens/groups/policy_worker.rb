# frozen_string_literal: true

module PersonalAccessTokens
  module Groups
    class PolicyWorker
      include ApplicationWorker

      data_consistency :always

      sidekiq_options retry: 3

      idempotent!

      queue_namespace :personal_access_tokens
      feature_category :system_access

      def perform(group_id)
        # no-op
        #
        # The worker is scheduled for removal by https://gitlab.com/gitlab-org/gitlab/-/work_items/629539
      end
    end
  end
end
