# frozen_string_literal: true

module Ai
  module Catalog
    module Items
      class BaseAuditEventMessageService
        def initialize(event_type, item, params = {})
          @event_type = event_type
          @item = item
          @params = params
          @old_definition = params[:old_definition]
          @current_user = params[:current_user]
        end

        def messages
          validate_schema_version!

          case event_type
          when "create_ai_catalog_#{item_type}"
            create_messages
          when "update_ai_catalog_#{item_type}"
            update_messages
          when "delete_ai_catalog_#{item_type}"
            delete_messages
          when "enable_ai_catalog_#{item_type}"
            enable_messages
          when "disable_ai_catalog_#{item_type}"
            disable_messages
          when "update_enabled_ai_catalog_#{item_type}"
            update_enabled_messages
          when 'restore_ai_catalog_item'
            restore_messages
          else
            []
          end
        end

        private

        attr_reader :current_user, :event_type, :item, :old_definition, :params

        def item_type
          raise NotImplementedError, "#{self.class} must implement #item_type"
        end

        def item_type_label
          "AI #{item.human_item_type}"
        end

        def expected_schema_version
          raise NotImplementedError, "#{self.class} must implement #expected_schema_version"
        end

        def validate_schema_version!
          return if item.blank? || item.latest_version.blank?

          actual_version = item.latest_version.schema_version
          expected_version = expected_schema_version

          return if actual_version == expected_version

          raise "Schema version mismatch for #{item_type_label}: expected #{expected_version}, " \
            "got #{actual_version}. Please update #{self.class} to handle the new schema version."
        end

        def create_messages
          raise NotImplementedError, "#{self.class} must implement #create_messages"
        end

        def update_messages
          messages = []

          change_descriptions = build_change_descriptions
          messages << "Updated #{item_type_label}: #{change_descriptions.join(', ')}" if change_descriptions.any?

          messages << update_visibility_message

          messages << version_message(item.latest_version) if version_created_or_released?

          messages.compact!

          messages << "Updated #{item_type_label}" if messages.empty?

          messages
        end

        def build_change_descriptions
          raise NotImplementedError, "#{self.class} must implement #build_change_descriptions"
        end

        def delete_messages
          ["Deleted #{item_type_label}"]
        end

        def enable_messages
          scope = params[:scope] || 'project/group'
          version_name = item_consumer_version(params[:item_consumer])

          ["Enabled #{item_type_label} for #{scope}: Pinned to #{version_name}"]
        end

        def disable_messages
          scope = params[:scope] || 'project/group'
          ["Disabled #{item_type_label} for #{scope}"]
        end

        def update_enabled_messages
          item_consumer = params[:item_consumer]

          return [] unless item_consumer.previous_changes.key?('pinned_version_prefix')

          ["Updated enabled #{item_type_label} to #{item_consumer_version(item_consumer)}"]
        end

        def restore_messages
          source_version = params[:source_version]
          new_version = params[:new_version]

          ["Restored version #{source_version.version} as new latest version " \
            "#{new_version.version} for #{item_type_label}"]
        end

        def get_definition_comparison
          [old_definition, item.latest_version.definition]
        end

        def visibility_label
          item.visibility
        end

        def update_visibility_message
          return unless visibility_updated?

          "Made #{item_type_label} #{visibility_label}"
        end

        def visibility_updated?
          update_visibility_change.present? && update_visibility_change[0] != update_visibility_change[1]
        end

        def update_visibility_change
          item.previous_changes['visibility']
        end

        def version_created_or_released?
          version_changes = item.latest_version.previous_changes
          version_changes.key?('id') || version_changes.key?('release_date')
        end

        def version_message(version)
          if version.draft?
            "Created new draft version #{version.version} of #{item_type_label}"
          else
            "Released version #{version.version} of #{item_type_label}"
          end
        end

        def format_list(items)
          return '[]' if items.blank?

          "[#{items.join(', ')}]"
        end

        def item_consumer_version(item_consumer)
          if item_consumer.pinned_version_prefix.present?
            "version #{item_consumer.pinned_version_prefix}"
          else
            "latest version"
          end
        end
      end
    end
  end
end
