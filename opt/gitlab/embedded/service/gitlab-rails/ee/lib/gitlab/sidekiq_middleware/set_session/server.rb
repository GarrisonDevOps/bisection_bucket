# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module SetSession
      class Server
        SESSION_ID_HASH_KEY = 'set_session_id'

        def call(_worker, job, _queue)
          if job.key?(SESSION_ID_HASH_KEY)
            session_id = job[SESSION_ID_HASH_KEY]
            session = ActiveSession.sessions_from_ids([session_id]).first if session_id
            session ||= {}
            session = session.with_indifferent_access
            session[SESSION_ID_HASH_KEY] = session_id # Allows nested sidekiq job to be scheduled with session id

            ::Gitlab::Session.with_session(session) do
              yield
            end
          else
            yield
          end
        end
      end
    end
  end
end
