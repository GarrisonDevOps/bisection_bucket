# frozen_string_literal: true

module ArtifactRegistry
  module CachesClient
    extend ActiveSupport::Concern
    include Gitlab::Utils::StrongMemoize

    def artifact_registry_client(current_user:)
      strong_memoize_with(:artifact_registry_client, current_user) do
        # self is the organization the request addresses, so the per-user token
        # is minted for it rather than for the user's home organization.
        ::ArtifactRegistry::Client.new(current_user: current_user, organization: self)
      end
    end

    # Service-authenticated client for the render path: the per-user client above
    # requires a current_user this caller does not have.
    def artifact_registry_service_client
      artifact_registry_client(current_user: nil)
    end
  end
end
