# frozen_string_literal: true

module EE
  module Types
    module Notes
      module NoteableInterface
        module ClassMethods
          def resolve_type(object, *)
            case object
            when ::Vulnerability
              ::Types::VulnerabilityType
            when ::Epic
              ::Types::EpicType
            when ::ComplianceManagement::Projects::ComplianceViolation
              ::Types::ComplianceManagement::Projects::ComplianceViolationType
            else
              super
            end
          end
        end

        def self.prepended(base)
          base.singleton_class.prepend(ClassMethods)
        end
      end
    end
  end
end
