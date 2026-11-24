# frozen_string_literal: true

module EE
  module WorkItems
    module DataSync
      module Widgets
        module LinkedItems
          extend ::Gitlab::Utils::Override

          BATCH_SIZE = ::WorkItems::DataSync::Widgets::Base::BATCH_SIZE

          private

          override :recreate_related_items
          def recreate_related_items
            super

            source_legacy_epic = work_item.sync_object
            target_legacy_epic = target_work_item.sync_object
            return unless source_legacy_epic && target_legacy_epic

            related_epic_links_by_source = ::Epic::RelatedEpicLink.for_source(source_legacy_epic)
            related_epic_links_by_source.each_batch(of: BATCH_SIZE, column: :target_id) do |links_batch|
              new_links = new_epic_links(links_batch, reference_attribute: 'source_id')
              ::Epic::RelatedEpicLink.insert_all(new_links) if new_links.any?
            end

            related_epic_links_by_target = ::Epic::RelatedEpicLink.for_target(source_legacy_epic)
            related_epic_links_by_target.each_batch(of: BATCH_SIZE, column: :source_id) do |links_batch|
              new_links = new_epic_links(links_batch, reference_attribute: 'target_id')
              ::Epic::RelatedEpicLink.insert_all(new_links) if new_links.any?
            end
          end

          def new_epic_links(links_batch, reference_attribute:)
            links_batch.map do |link|
              source_reference = reference_attribute == 'source_id' ? target_work_item : link.source.sync_object
              target_reference = reference_attribute == 'target_id' ? target_work_item : link.target.sync_object
              issue_link = IssueLink.for_source(source_reference).for_target(target_reference).first

              link.attributes.except('id', 'namespace_id').merge(
                reference_attribute => target_work_item.sync_object.id,
                issue_link_id: issue_link.id
              )
            end
          end
        end
      end
    end
  end
end
