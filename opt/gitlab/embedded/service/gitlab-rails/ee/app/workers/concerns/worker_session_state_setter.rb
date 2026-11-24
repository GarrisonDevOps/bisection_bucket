# frozen_string_literal: true

module WorkerSessionStateSetter # rubocop:disable Gitlab/BoundedContexts -- Shared
  extend ActiveSupport::Concern

  class_methods do
    def perform_async(...)
      # Passing in session information is required as Llm::CompletionWorker needs to pass it along to
      #   Llm::Internal::CompletionService so that the resource_authorized? check takes SAML session into account
      with_ip_address_state
        .set(
          ::Gitlab::SidekiqMiddleware::SetSession::Server::SESSION_ID_HASH_KEY =>
          ::Gitlab::Session.session_id_for_worker
        ).perform_async(...)
    end
  end
end
