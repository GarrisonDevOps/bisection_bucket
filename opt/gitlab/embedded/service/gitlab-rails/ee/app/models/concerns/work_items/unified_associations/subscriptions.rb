# frozen_string_literal: true

module WorkItems
  module UnifiedAssociations
    module Subscriptions
      extend ActiveSupport::Concern

      included do
        # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
        has_many :own_subscriptions, dependent: :destroy, class_name: 'Subscription', as: :subscribable
        # rubocop:enable Cop/ActiveRecordDependent -- legacy usage
        has_many :subscriptions, as: :subscribable do
          def load_target
            return super unless proxy_association.owner.unified_associations?

            proxy_association.target = scope.to_a unless proxy_association.loaded?

            proxy_association.loaded!
            proxy_association.target
          end

          def find_by(arg, *args)
            return super unless proxy_association.owner.unified_associations?
            return super if block_given?

            # When records exist for the subscribable and the synced object return the latest one
            scope.where(arg, *args).order(id: :desc).first
          end

          def scope
            return super unless proxy_association.owner.unified_associations?

            Subscription.from_union(
              [
                proxy_association.owner.sync_object.own_subscriptions || Subscription.none,
                proxy_association.owner.own_subscriptions
              ]
            )
          end
        end
      end

      def unified_subscriptions(objects_relation, sync_objects_relation, user)
        ::Subscription.from_union(
          [
            Subscription.where(
              subscribable_id: objects_relation.flat_map(&:first)[0],
              subscribable_type: objects_relation.flat_map(&:second)[0],
              user: user
            ),
            Subscription.where(
              subscribable_id: sync_objects_relation.flat_map(&:first)[0],
              subscribable_type: sync_objects_relation.flat_map(&:second)[0],
              user: user
            )
          ]).order('id DESC').limit(1)
            .group_by { |subscription| [subscription.subscribable_id, subscription.subscribable_type] }
      end
    end
  end
end
