# frozen_string_literal: true

module WorkItems
  module UnifiedAssociations
    module Events
      extend ActiveSupport::Concern

      included do
        has_many :own_events, ->(record) { where(target_type: [record.class.name, record.class.base_class.name].uniq) },
          # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
          foreign_key: :target_id, inverse_of: :target, class_name: 'Event', dependent: :delete_all
        # rubocop:enable Cop/ActiveRecordDependent -- legacy usage
        has_many :events, ->(record) { where(target_type: [record.class.name, record.class.base_class.name].uniq) },
          # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
          foreign_key: :target_id, inverse_of: :target, class_name: 'Event', dependent: :delete_all do
          # rubocop:enable Cop/ActiveRecordDependent -- legacy usage
          def load_target
            return super unless proxy_association.owner.unified_associations?

            proxy_association.target = scope.to_a unless proxy_association.loaded?

            proxy_association.loaded!
            proxy_association.target
          end

          # important to have this method overwritten as most collection proxy method methods are delegated to the scope
          def scope
            return super unless proxy_association.owner.unified_associations?

            Event.from_union(
              [
                proxy_association.owner.sync_object&.own_events || Event.none,
                proxy_association.owner.own_events
              ],
              remove_duplicates: true
            )
          end
        end
      end
    end
  end
end
