# frozen_string_literal: true

module Gitlab
  # Shared by controllers and API endpoints. The host must provide `current_user`
  # and `check_rate_limit!` (CheckRateLimit or API::Helpers::RateLimiter), and a
  # block is handled the way that `check_rate_limit!` handles it.
  module NotesCreateRateLimit
    # Options for checking the notes_create limit, also used outside web
    # requests by {Notes::CreateRateLimiter}.
    #
    # A cost above the limit could never succeed, so it is capped at the limit.
    #
    # @param user [User] the user the notes are counted against
    # @param cost [Integer, nil] how many notes to count, 1 when omitted
    # @return [Hash] options for `throttled?` or `check_rate_limit!`
    def self.rate_limit_options(user, cost: nil)
      settings = Gitlab::CurrentSettings.current_application_settings

      options = {
        scope: { user: user },
        users_allowlist: settings.notes_create_limit_allowlist
      }
      options[:cost] = [cost, settings.notes_create_limit].min if cost

      options
    end

    def check_notes_create_rate_limit!(cost: nil, &block)
      check_rate_limit!(:notes_create, **NotesCreateRateLimit.rate_limit_options(current_user, cost: cost), &block)
    end
  end
end
