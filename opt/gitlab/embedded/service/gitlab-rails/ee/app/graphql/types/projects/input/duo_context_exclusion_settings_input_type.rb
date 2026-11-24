# frozen_string_literal: true

module Types
  module Projects
    module Input
      class DuoContextExclusionSettingsInputType < BaseInputObject
        graphql_name 'DuoContextExclusionSettingsInput'
        description 'Input for Duo context exclusion settings'

        argument :exclusion_rules,
          [String],
          required: true,
          description: 'List of rules for excluding files from Duo context.'
      end
    end
  end
end
