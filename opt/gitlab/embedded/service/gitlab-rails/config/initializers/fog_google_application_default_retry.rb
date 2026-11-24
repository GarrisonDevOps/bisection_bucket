# frozen_string_literal: true

# google-cloud-env caches "no metadata server" for the life of the process after a single
# metadata timeout, so every later application default credentials lookup fails until restart.
# Reset that cache and retry once. See https://github.com/googleapis/ruby-cloud-env/issues/110
module Gitlab
  module FogGoogleApplicationDefaultRetry
    private

    def process_application_default_auth(options)
      super
    rescue RuntimeError => e
      raise unless e.message == ::Google::Auth::NOT_FOUND_ERROR
      raise unless ::Google::Cloud.env.compute_metadata.existence_immediate == :no

      ::Google::Auth::GCECredentials.reset_cache

      super
    end
  end
end

Fog::Google::Shared.prepend(Gitlab::FogGoogleApplicationDefaultRetry)
