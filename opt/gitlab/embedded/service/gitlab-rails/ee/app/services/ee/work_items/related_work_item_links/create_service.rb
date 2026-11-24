# frozen_string_literal: true

module EE
  module WorkItems
    module RelatedWorkItemLinks
      module CreateService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        def execute
          if params[:link_type].present? && !link_type_available?
            return error(_('Blocked work items are not available for the current subscription tier'), 403)
          end

          result = if sync_related_epic_link?
                     ApplicationRecord.transaction do
                       response = super
                       if response[:status] == :error
                         raise ::WorkItems::SyncAsEpic::SyncAsEpicError.new(response[:message], response[:http_status])
                       end

                       create_synced_related_epic_link!
                       response
                     end
                   else
                     super
                   end

          if result[:status] == :success && new_links.any?
            # Needs to be called outside of transaction
            # because it spawns sidekiq jobs.
            create_notes_async
          end

          result
        rescue ::WorkItems::SyncAsEpic::SyncAsEpicError => error
          ::Gitlab::ErrorTracking.track_exception(error, work_item_id: issuable.id)

          error(error.message, error.http_status || 422)
        end

        private

        def extractor_context
          return { group: issuable.namespace } if issuable.namespace.is_a?(Group)

          super
        end

        def references(extractor)
          super + ::WorkItem.id_in(extractor.epics.map(&:issue_id))
        end

        # This override prevents calling :create_notes_async
        # inside a transaction.
        # Can be removed after migration of epics to work_items.
        override :after_execute
        def after_execute; end

        def link_type_available?
          return true unless [link_class::TYPE_BLOCKS, link_class::TYPE_IS_BLOCKED_BY].include?(params[:link_type])

          issuable.resource_parent.licensed_feature_available?(:blocked_work_items)
        end

        override :linked_ids
        def linked_ids(created_links)
          return super unless params[:link_type] == 'is_blocked_by'

          created_links.collect(&:source_id)
        end

        def create_synced_related_epic_link!
          new_links.each do |work_item_link|
            # RelatedEpicLink can only link an epic to an epic. We therefore need to skip the links where not both
            # work items are epics.
            next if work_item_link.source.synced_epic.nil?
            next if work_item_link.target.synced_epic.nil?

            epic_link = ::Epic::RelatedEpicLink.find_or_initialize_from_work_item_link(work_item_link)

            log_and_raise_sync_error!(epic_link) unless epic_link.save
          end
        end

        def log_and_raise_sync_error!(epic_link)
          error_message = epic_link.errors&.full_messages&.to_sentence
          return unless error_message

          ::Gitlab::EpicWorkItemSync::Logger.error(
            message: "Not able to create related epic links",
            error_message: error_message,
            group_id: issuable.namespace.id,
            work_item_id: issuable.id
          )
          raise ::WorkItems::SyncAsEpic::SyncAsEpicError, error_message
        end

        def sync_related_epic_link?
          issuable.group_epic_work_item? &&
            issuable.synced_epic.present?
        end
      end
    end
  end
end
