# frozen_string_literal: true

module ArtifactRegistry
  # Reads the ADR-020 service token from the mounted file, nil when unconfigured
  # so an unwired client fails closed. A consumer may inject its own provider.
  class ServiceCredential
    include Gitlab::Utils::StrongMemoize

    # RFC 7230 field-value bytes (visible ASCII plus SP and HTAB).
    VALID_TOKEN_CHARS = /\A[\x21-\x7e\x20\x09]+\z/

    def token
      path = Configuration.service_token_secret_file
      return if path.blank?

      # chomp, not strip: only the trailing newline a mounted secret carries is
      # noise. presence then rejects an empty or whitespace-only file.
      #
      # No symlink/realpath guard, matching the iam_data_access_service mirror:
      # the path comes from operator-controlled gitlab.yml, not user input.
      value = File.read(path).chomp.presence
      return if value.nil?

      # A value with header-invalid bytes means the wrong file was mounted;
      # reject it here rather than let Net::HTTP raise an opaque ArgumentError.
      raise Client::AuthorizationError, 'service token has invalid characters' unless
        value.match?(VALID_TOKEN_CHARS)

      value
    rescue SystemCallError
      # A broken mount is fail-loud, not fail-closed. Re-raised typed so the
      # client's error contract (caching, 503 render) engages, not an untyped 500.
      raise Client::AuthorizationError, 'service token unreadable'
    end
    strong_memoize_attr :token
  end
end
