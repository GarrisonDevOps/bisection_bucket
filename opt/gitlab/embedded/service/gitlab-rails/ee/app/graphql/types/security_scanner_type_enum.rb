# frozen_string_literal: true

module Types
  class SecurityScannerTypeEnum < BaseEnum
    graphql_name 'SecurityScannerType'
    description 'The type of the security scanner'

    Enums::Security.analyzer_types.each_key do |scanner|
      upcase_type = scanner.upcase.to_s
      human_type = case scanner
                   when :dast, :sast then upcase_type
                   when :api_fuzzing then 'API fuzzing'
                   when :sast_advanced then 'SAST advanced'
                   when :sast_iac then 'SAST IaC'
                   else scanner.to_s.humanize
                   end

      value upcase_type, description: "#{human_type} scanner"
    end
  end
end
