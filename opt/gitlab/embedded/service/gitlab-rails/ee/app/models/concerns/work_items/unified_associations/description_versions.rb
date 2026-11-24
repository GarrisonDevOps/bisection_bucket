# frozen_string_literal: true

module WorkItems
  module UnifiedAssociations
    module DescriptionVersions
      extend ActiveSupport::Concern

      included do
        # rubocop:disable Rails/InverseOf -- this is temporary and polymorphic so no inverse for now
        has_many :own_description_versions, class_name: 'DescriptionVersion',
          foreign_key: "#{base_class.name.underscore}_id"
        has_many :description_versions, foreign_key: "#{base_class.name.underscore}_id" do
          def load_target
            return super unless proxy_association.owner.unified_associations?

            proxy_association.target = scope.to_a unless proxy_association.loaded?

            proxy_association.loaded!
            proxy_association.target
          end

          def scope
            DescriptionVersion.from_union(
              [
                proxy_association.owner.sync_object&.own_description_versions || DescriptionVersion.none,
                proxy_association.owner.own_description_versions
              ],
              remove_duplicates: true
            )
          end

          def find(*args)
            return super unless proxy_association.owner.unified_associations?
            return super if block_given?

            scope.find(*args)
          end
        end
        # rubocop:enable Rails/InverseOf
      end
    end
  end
end
