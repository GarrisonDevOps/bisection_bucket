# frozen_string_literal: true

module Types
  module Projects
    module ComplianceStandards
      class AdherenceCheckNameEnum < BaseEnum
        graphql_name 'ComplianceStandardsAdherenceCheckName'
        description 'Name of the check for the compliance standard.'

        ::Enums::Projects::ComplianceStandards::Adherence.check_name.each_key do |check|
          description = if check.to_s == 'prevent_approval_by_merge_request_author'
                          'Prevent approval by merge request creator (author)'
                        else
                          check.to_s.humanize
                        end

          value check.to_s.upcase, value: check.to_s, description: description
        end
      end
    end
  end
end
