# frozen_string_literal: true

module Types
  module Vulnerabilities
    class CvssSeverityEnum < BaseEnum
      graphql_name 'CvssSeverity'
      description 'Values for a CVSS severity'

      # Strings from https://github.com/0llirocks/cvss-suite/blob/1cb50933744b7f5bac1fbab5e80bf9b214a24f3d/lib/cvss_suite/cvss.rb#L49
      value 'NONE', 'Not a vulnerability.', value: 'None'
      %w[Low Medium High Critical].each do |severity|
        value severity.upcase, description: "#{severity} severity.", value: severity
      end
    end
  end
end
