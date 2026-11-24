# frozen_string_literal: true

module Security
  module SecretDetection
    # Which token types can be verified, and for which scanner's findings.
    # One lookup over both registries: PartnerTokens::Registry (vendor
    # tokens) and TokenLookupService (GitLab's own tokens).
    module ValiditySupport
      # -> :supported | :supported_elsewhere | :unsupported
      #
      # :supported_elsewhere: only another scanner's findings are verified
      # for this token type.
      def self.state(token_type:, source:)
        targets = enabled_targets(token_type)

        return :unsupported if targets.empty?

        targets.include?(source) ? :supported : :supported_elsewhere
      end

      # A display state when no verification result can exist for this finding,
      # or nil when it is supported and the stored token status applies instead.
      def self.display_state(token_type:, source:)
        case state(token_type: token_type, source: source)
        when :unsupported then 'no_vendor_support'
        when :supported_elsewhere then 'not_checked_by_analyzer'
        end
      end

      # Union of the scanners whose findings are verified for this token type.
      # A token type lives in exactly one registry, so the union is that
      # registry's own list.
      def self.enabled_targets(token_type)
        PartnerTokens::Registry.enabled_targets_for(token_type).to_a |
          TokenLookupService.enabled_targets_for(token_type).to_a
      end
    end
  end
end
