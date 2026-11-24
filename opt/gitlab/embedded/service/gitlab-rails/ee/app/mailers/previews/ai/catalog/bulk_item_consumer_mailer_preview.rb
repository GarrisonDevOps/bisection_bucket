# frozen_string_literal: true

module Ai
  module Catalog
    class BulkItemConsumerMailerPreview < ActionMailer::Preview
      def bulk_create_result_all_success
        Ai::Catalog::BulkItemConsumerMailer.bulk_create_result_email(
          user: user,
          item: item,
          successful_count: 5,
          failures: []
        )
      end

      def bulk_create_result_with_failures
        Ai::Catalog::BulkItemConsumerMailer.bulk_create_result_email(
          user: user,
          item: item,
          successful_count: 3,
          failures: project_ids.last(2).map do |id|
            { project_id: id, error_message: 'Permission denied' }
          end
        )
      end

      def bulk_create_result_all_failed
        Ai::Catalog::BulkItemConsumerMailer.bulk_create_result_email(
          user: user,
          item: item,
          successful_count: 0,
          failures: project_ids.first(3).map do |id|
            { project_id: id, error_message: 'Permission denied' }
          end
        )
      end

      private

      def user
        User.first
      end

      def item
        ::Ai::Catalog::Item.first || fake_item
      end

      def project_ids
        @project_ids ||= Project.limit(5).ids # rubocop:disable CodeReuse/ActiveRecord -- preview helper
      end

      def fake_item
        ::Ai::Catalog::Item.new(id: 1, name: 'Code Review Agent', item_type: :agent)
      end
    end
  end
end
