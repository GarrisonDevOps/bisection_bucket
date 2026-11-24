# frozen_string_literal: true

module Gitlab
  # Shared by controllers and API endpoints. The host must provide `current_user`
  # and `check_rate_limit!` (CheckRateLimit or API::Helpers::RateLimiter), and a
  # block is handled the way that `check_rate_limit!` handles it.
  module NotesUpdateRateLimit
    # Reuses the notes_create allowlist so one list exempts a user from both limits.
    def check_notes_update_rate_limit!(&block)
      return unless Feature.enabled?(:notes_update_rate_limit, current_user)

      settings = Gitlab::CurrentSettings.current_application_settings

      check_rate_limit!(
        :notes_update,
        scope: { user: current_user },
        users_allowlist: settings.notes_create_limit_allowlist,
        &block
      )
    end
  end
end
