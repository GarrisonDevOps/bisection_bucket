# frozen_string_literal: true

module Security
  module Attributes
    class CleanupProjectToSecurityAttributeWorker
      include ApplicationWorker

      version 1
      data_consistency :sticky
      deduplicate :until_executed, including_scheduled: true
      feature_category :security_asset_inventories
      idempotent!
      urgency :low

      defer_on_database_health_signal :gitlab_sec, [:project_to_security_attributes]

      def perform(attribute_ids = nil, category_id = nil)
        return unless attribute_ids

        @attribute_ids = attribute_ids
        @category_id = category_id

        result = ::Security::Attributes::ProjectToSecurityAttributeDestroyService.new(
          attribute_ids: attribute_ids
        ).execute

        unless result.success?
          Gitlab::ErrorTracking.track_and_raise_exception(
            StandardError.new(result.message),
            attribute_ids: attribute_ids,
            category_id: category_id,
            worker: self.class.name
          )
        end

        hard_delete_attributes
        hard_delete_category if category_id

        result
      end

      private

      attr_reader :attribute_ids, :category_id

      def hard_delete_attributes
        Security::Attribute.really_destroy_all!(attribute_ids)
      end

      def hard_delete_category
        Security::Category.really_destroy_by_id!(category_id)
      end
    end
  end
end
