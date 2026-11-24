# frozen_string_literal: true

module Gitlab
  module Scim
    module SchemaDefinitions
      # Base class for SCIM schema definitions (RFC 7643 Section 7).
      #
      # Subclasses describe only the attributes GitLab actually processes or
      # returns, so identity providers do not map attributes that are ignored.
      class Base
        class << self
          def schema_id
            raise NotImplementedError
          end

          def schema_name
            raise NotImplementedError
          end

          def description
            raise NotImplementedError
          end

          # @param context [Symbol] the SCIM API context, `:group` or `:instance`
          def attributes(context:)
            raise NotImplementedError
          end

          def to_h(context:)
            {
              id: schema_id,
              name: schema_name,
              description: description,
              attributes: attributes(context: context)
            }
          end

          private

          # rubocop:disable Metrics/ParameterLists -- mirrors the RFC 7643 attribute characteristics
          def attribute(
            name, description, type: 'string', required: false, multi_valued: false,
            mutability: 'readWrite', returned: 'default', uniqueness: 'none', case_exact: false,
            sub_attributes: nil, reference_types: nil)
            {
              name: name,
              type: type,
              multiValued: multi_valued,
              description: description,
              required: required,
              caseExact: case_exact,
              mutability: mutability,
              returned: returned,
              uniqueness: uniqueness,
              subAttributes: sub_attributes,
              referenceTypes: reference_types
            }.compact
          end
          # rubocop:enable Metrics/ParameterLists
        end
      end
    end
  end
end
