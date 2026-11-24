# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    module RelatedEpicLinks
      class CreateService
        def initialize(legacy_epic, user, params)
          @legacy_epic = legacy_epic
          @user = user
          @params = params
        end

        def execute
          WorkItems::RelatedWorkItemLinks::CreateService
            .new(legacy_epic.work_item, user,
              {
                target_issuable: target_work_items,
                link_type: params[:link_type]
              })
            .execute
            .then { |result| transform_result(result) }
        end

        private

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

        def referenced_epics
          extractor = Gitlab::ReferenceExtractor.new(nil, user)
          extractor.analyze(params[:issuable_references]&.join(' '), { group: legacy_epic.group })
          extractor.epics
        end

        def transform_result(result)
          if result[:status] == :error
            result[:message] = transformed_error_message(result) || result[:message]
          else
            result[:created_references] = result[:created_references]&.map(&:synced_related_epic_link)
            result.delete(:message)
          end

          result
        end

        def transformed_error_message(result)
          ::Gitlab::WorkItems::IssuableLinks::ErrorMessage.new(target_type: 'epic')
            .for_http_status(result[:http_status])
        end

        attr_reader :legacy_epic, :user, :params
      end
    end
  end
end
