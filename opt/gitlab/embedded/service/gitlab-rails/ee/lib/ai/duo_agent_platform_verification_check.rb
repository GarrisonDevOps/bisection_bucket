# frozen_string_literal: true

module Ai
  module DuoAgentPlatformVerificationCheck
    # The probe makes a real gRPC call authenticated as `user`, so its result is not
    # safe to cache across users; this only saves repeat probes from the same admin
    # polling the settings page.
    PROBE_CACHE_TTL = 30.seconds

    def self.agentic_chat_verification_check_enabled?(user)
      return false unless Ability.allowed?(user, :manage_self_hosted_models_settings)

      probe_success?(user)
    end

    def self.probe_success?(user)
      Rails.cache.fetch(['agentic_chat_verification_check_probe', user.id], expires_in: PROBE_CACHE_TTL) do
        CloudConnector::StatusChecks::Probes::DuoAgentPlatformProbe.new(user, deployment: :self_hosted)
          .execute.success?
      end
    end
    private_class_method :probe_success?
  end
end
