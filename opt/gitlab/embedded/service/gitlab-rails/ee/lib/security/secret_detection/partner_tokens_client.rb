# frozen_string_literal: true

module Security
  module SecretDetection
    class PartnerTokensClient
      include Gitlab::Utils::StrongMemoize

      delegate :project, :token_type, :token_value, to: :finding, allow_nil: true
      attr_reader :finding

      def initialize(finding)
        @finding = finding
      end

      def rate_limited?
        limited = ::Gitlab::ApplicationRateLimiter.throttled?(
          partner_config[:rate_limit_key],
          scope: { project: project }
        )

        if limited
          record_rate_limit_hit
          log_rate_limit('Rate limit exceeded for partner token verification')
        end

        limited
      end

      def valid_config?
        !!(partner_config && token_type && token_value)
      end

      # token_type must be the detection rule id that actually matched token_value.
      # The verifier trusts that pairing instead of re-checking the shape, so the
      # entry point building the finding owns keeping them in step.
      def verify_token
        PartnerTokens::Registry.client_for(token_type).verify_token(token_value)
      end

      def partner_config
        PartnerTokens::Registry.partner_for(token_type)
      end
      strong_memoize_attr :partner_config

      private

      def record_rate_limit_hit
        ::Gitlab::Metrics::SecretDetection::PartnerTokens.increment_rate_limit_hits(
          limit_type: partner_config[:rate_limit_key].to_s
        )
      end

      def log_rate_limit(message)
        Gitlab::AppLogger.warn(
          message: message,
          finding_id: finding.id,
          project_id: project.id,
          project_path: project.full_path,
          token_type: token_type,
          rate_limit_key: partner_config[:rate_limit_key]
        )
      end
    end
  end
end
