# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module Items
        extend ActiveSupport::Concern

        included do |base|
          base.class_attribute(:registered_flows, instance_accessor: false, instance_predicate: false, default: [])
        end

        # Reference of the Business Logic Security Scan flow, for code outside its definition.
        BL_SECURITY_FLOW_REFERENCE = BlSecurity::Definition::REFERENCE

        class_methods do
          # Make sure static data is always loaded in English and let `translated_display_name` and
          # `translated_description` deal with translations when required.
          # This ensures catalog items records are created in English and translated on the fly when needed.
          def register_flow(definition)
            Gitlab::I18n.with_locale(:en) do
              configuration = definition.configuration
              reference = configuration[:foundational_flow_reference]

              # If a registered flow does not define a reference, validation will fail down the road
              # when FixedItems loads the instances data. We just skip method definition here to avoid
              # breaking before the validation runs.
              if reference
                define_singleton_method(reference.parameterize(separator: "_")) do
                  find_by(foundational_flow_reference: reference)
                end
              end

              self.registered_flows += [configuration]
            end
          end

          def fixed_items
            registered_flows
          end
        end
      end
    end
  end
end
