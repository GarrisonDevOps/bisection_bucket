# frozen_string_literal: true

module EE
  module JiraConnect
    module SyncService
      extend ::Gitlab::Utils::Override

      # `Project#jira_subscription_exists?` returns `false` in EE when blocked by settings,
      # which should always be guarding calls to this service.
      # As a secondary guard we check the settings here also.
      override :execute
      def execute(**_args)
        super unless ::Integrations::JiraCloudApp.blocked_by_settings?(log: true)
      end
    end
  end
end
