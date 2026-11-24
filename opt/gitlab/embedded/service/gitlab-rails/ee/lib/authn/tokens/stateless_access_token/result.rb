# frozen_string_literal: true

module Authn
  module Tokens
    class StatelessAccessToken
      # Returned by StatelessAccessToken.issue; duck-types the interface callers
      # already expect from an OauthAccessToken (plaintext_token, scopes,
      # expires_in, expires_at).
      Result = Struct.new(:plaintext_token, :scopes, :expires_in, :expires_at, keyword_init: true)
    end
  end
end
