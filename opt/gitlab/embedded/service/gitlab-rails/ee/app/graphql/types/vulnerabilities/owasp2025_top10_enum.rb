# frozen_string_literal: true

module Types
  module Vulnerabilities
    class Owasp2025Top10Enum < BaseEnum
      graphql_name 'VulnerabilityOwasp2025Top10'
      description '`OwaspTop10` vulnerability categories for OWASP 2025'

      # GraphQL names can only contain _, letter, numbers.
      # See: https://spec.graphql.org/draft/#sec-Names
      # So working around by having only label and year with an underscore.
      NAME_MAP = {
        "A01:2025-Broken Access Control" => "A01_2025",
        "A02:2025-Security Misconfiguration" => "A02_2025",
        "A03:2025-Software Supply Chain Failures" => "A03_2025",
        "A04:2025-Cryptographic Failures" => "A04_2025",
        "A05:2025-Injection" => "A05_2025",
        "A06:2025-Insecure Design" => "A06_2025",
        "A07:2025-Authentication Failures" => "A07_2025",
        "A08:2025-Software or Data Integrity Failures" => "A08_2025",
        "A09:2025-Security Logging and Alerting Failures" => "A09_2025",
        "A10:2025-Mishandling of Exceptional Conditions" => "A10_2025"
      }.freeze

      NAME_MAP.each do |owasp_key, owasp_value|
        value owasp_value.upcase, value: owasp_key,
          experiment: { milestone: '19.0' },
          description: "#{owasp_key}, OWASP top 10 2025 category."
      end

      value 'NONE', value: ::Security::VulnerabilityReadsFinder::FILTER_NONE,
        experiment: { milestone: '19.0' },
        description: 'No OWASP top 10 2025 category.'
    end
  end
end
