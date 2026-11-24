# frozen_string_literal: true

module Types
  module Projects
    module ComplianceStandards
      class ProjectAdherenceInputType < BaseInputObject
        graphql_name 'ComplianceStandardsProjectAdherenceInput'

        argument :check_name, AdherenceCheckNameEnum,
          required: false,
          description: 'Name of the check for the compliance standard.'

        argument :standard, AdherenceStandardEnum,
          required: false,
          description: 'Name of the compliance standard.'
      end
    end
  end
end
