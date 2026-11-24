# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    module EpicLinks
      class CreateService
        include ::Gitlab::Utils::StrongMemoize

        def initialize(legacy_epic, user, params)
          @legacy_epic = legacy_epic
          @user = user
          @params = params
          @previous_parent_links = {}
        end

        def execute
          @previous_parent_links = target_work_items.each_with_object({}) do |work_item, hash|
            hash[work_item.id] = work_item.parent_link.work_item_parent_id if work_item.parent_link&.work_item_parent_id
          end

          ::WorkItems::UpdateService.new(
            container: parent_work_item.resource_parent,
            current_user: user,
            params: {},
            widget_params: { hierarchy_widget: { children: target_work_items } }
          ).execute(parent_work_item).then do |result|
            Gitlab::WorkItems::LegacyEpics::TransformServiceResponse.new(result:)
              .transform(created_references_lambda: -> { created_references },
                error_message_lambda: -> { error_message_creator })
          end
        end

        private

        attr_reader :legacy_epic, :user, :params, :previous_parent_links

        def parent_work_item
          legacy_epic.work_item
        end
        strong_memoize_attr :parent_work_item

        def target_work_items
          target_issuable = params[:target_issuable]

          if params[:issuable_references].present?
            WorkItem.id_in(referenced_epics.filter_map(&:issue_id))
          elsif target_issuable
            WorkItem.id_in(Array.wrap(target_issuable).map(&:issue_id))
          else
            []
          end
        end
        strong_memoize_attr :target_work_items

        def referenced_epics
          extractor = Gitlab::ReferenceExtractor.new(nil, user)
          extractor.analyze(params[:issuable_references]&.join(' '), { group: legacy_epic.group })
          extractor.epics
        end

        def created_references
          target_work_items.filter_map do |work_item|
            next if previous_parent_links[work_item.id] == work_item.reset.parent_link&.work_item_parent_id
            next if work_item.parent_link.nil?

            work_item.synced_epic
          end
        end

        def error_message_creator
          ::Gitlab::WorkItems::IssuableLinks::ErrorMessage.new(target_type: 'epic')
        end
      end
    end
  end
end
