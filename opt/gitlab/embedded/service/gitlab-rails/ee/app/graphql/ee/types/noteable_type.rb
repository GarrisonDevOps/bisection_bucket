# frozen_string_literal: true

module EE
  module Types
    # Adds the EE noteables to the `NoteableType` union. `Types::NoteableType.resolve_type`
    # already delegates to `Types::Notes::NoteableInterface.resolve_type` (whose EE override
    # maps these objects to their types), so only `possible_types` needs extending here.
    module NoteableType # rubocop:disable Gitlab/BoundedContexts -- EE extension of the CE Types::NoteableType
      extend ActiveSupport::Concern

      prepended do
        possible_types ::Types::VulnerabilityType,
          ::Types::EpicType,
          ::Types::ComplianceManagement::Projects::ComplianceViolationType
      end
    end
  end
end
