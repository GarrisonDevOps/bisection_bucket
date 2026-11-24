# frozen_string_literal: true

module Types
  module Vulnerabilities
    class Owasp2021Top10Enum < BaseEnum
      graphql_name 'VulnerabilityOwasp2021Top10'
      description '`OwaspTop10` vulnerability categories for OWASP 2021'

      # GraphQL names can only contain _, letter, numbers.
      # See: https://spec.graphql.org/draft/#sec-Names
      # So working around by having only label and year with an underscore.
      # 2021 switched to zero-padded identifiers, previous mapping is temporary
      # to be fixed with https://gitlab.com/gitlab-org/gitlab/-/issues/429565
      NAME_MAP = {
        "A1:2021-Broken Access Control" => "A1_2021",
        "A01:2021-Broken Access Control" => "A01_2021",
        "A2:2021-Cryptographic Failures" => "A2_2021",
        "A02:2021-Cryptographic Failures" => "A02_2021",
        "A3:2021-Injection" => "A3_2021",
        "A03:2021-Injection" => "A03_2021",
        "A4:2021-Insecure Design" => "A4_2021",
        "A04:2021-Insecure Design" => "A04_2021",
        "A5:2021-Security Misconfiguration" => "A5_2021",
        "A05:2021-Security Misconfiguration" => "A05_2021",
        "A6:2021-Vulnerable and Outdated Components" => "A6_2021",
        "A06:2021-Vulnerable and Outdated Components" => "A06_2021",
        "A7:2021-Identification and Authentication Failures" => "A7_2021",
        "A07:2021-Identification and Authentication Failures" => "A07_2021",
        "A8:2021-Software and Data Integrity Failures" => "A8_2021",
        "A08:2021-Software and Data Integrity Failures" => "A08_2021",
        "A9:2021-Security Logging and Monitoring Failures" => "A9_2021",
        "A09:2021-Security Logging and Monitoring Failures" => "A09_2021",
        "A10:2021-Server-Side Request Forgery" => "A10_2021"
      }.with_indifferent_access.freeze

      ::Enums::Vulnerability::OWASP_TOP_10_BY_YEAR["2021"].each_key do |owasp_key|
        value NAME_MAP[owasp_key].upcase, value: owasp_key,
          experiment: { milestone: '18.1' },
          description: "#{owasp_key}, OWASP top 10 category."
      end

      value 'NONE', value: ::Security::VulnerabilityReadsFinder::FILTER_NONE, description: 'No OWASP top 10 category.'
    end
  end
end
