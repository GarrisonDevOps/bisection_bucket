# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    class SecretsManagerResponseError < CdotResponseError
      # CDot was unreachable or answered 5xx, so it failed rather than decided. Shared by
      # both endpoints: the resolver may replay last-known-good on it, a plain Error fails closed.
      UnavailableError = Class.new(self)
    end
  end
end
