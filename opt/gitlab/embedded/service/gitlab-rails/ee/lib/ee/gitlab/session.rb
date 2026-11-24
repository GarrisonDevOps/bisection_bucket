# frozen_string_literal: true

module EE
  module Gitlab
    module Session
      extend ActiveSupport::Concern

      class_methods do
        def session_id_for_worker
          session = current

          return unless session

          if session.is_a?(::ActionDispatch::Request::Session)
            # Read the https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171262 description
            # for more details of why options might be a hash
            session.options.is_a?(Hash) ? nil : session.id.private_id
          elsif session.respond_to?(:[]) # Hash-like
            session[::Gitlab::SidekiqMiddleware::SetSession::Server::SESSION_ID_HASH_KEY]
          else
            raise("Unsupported session class: #{session.class}")
          end
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
          nil
        end
      end
    end
  end
end
