# frozen_string_literal: true

module Namespaces
  module Storage
    class UsageExportService
      def self.execute(plan, user)
        new(plan, user).execute
      end

      def initialize(plan, user)
        @current_user = user
        @plan = plan
      end

      def execute
        return insufficient_permissions unless current_user.can_admin_all_resources?

        ServiceResponse.success(payload: csv_builder.render)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
        ServiceResponse.error(message: 'Failed to generate storage export')
      end

      private

      attr_reader :current_user, :plan

      def header_to_value_hash
        {
          'Namespace ID' => 'id',
          'Total Storage (B)' => 'storage_size',
          'Purchased Storage (B)' => ->(item) { purchased_storage(item) },
          'Free Storage Consumed (B)' => ->(item) { free_storage_consumed(item) },
          'First Notified' => ->(item) { item.namespace.namespace_limit.pre_enforcement_notification_at }
        }
      end

      def purchased_storage(item)
        item.namespace.additional_purchased_storage_size.megabytes
      end

      def free_storage_consumed(item)
        [item.storage_size - purchased_storage(item), 0].max
      end

      def csv_builder
        CsvBuilder.new(batch_iterator, header_to_value_hash)
      end

      def insufficient_permissions
        ServiceResponse.error(message: 'Insufficient permissions to generate storage export')
      end

      def batch_iterator
        Enumerator.new do |yielder|
          Namespace::RootStorageStatistics.each_batch(of: 1000) do |relation|
            relation.with_namespace_associations.each do |record|
              yielder << record if record_in_plan?(record)
            end
          end
        end
      end

      # Future iterations will support exporting a CSV for different plans
      # new conditions can be added per plan as required
      def record_in_plan?(record)
        case plan
        when 'free'
          !record.namespace.paid?
        else
          false
        end
      end
    end
  end
end
