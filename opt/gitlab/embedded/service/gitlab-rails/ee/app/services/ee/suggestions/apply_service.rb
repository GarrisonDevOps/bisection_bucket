# frozen_string_literal: true

module EE
  module Suggestions # rubocop:disable Gitlab/BoundedContexts -- EE override of CE Suggestions::ApplyService
    module ApplyService
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :update_suggestions
      def update_suggestions(result)
        super

        return unless result[:status] == :success

        track_fix_pipeline_suggestion_applied
      end

      def track_fix_pipeline_suggestion_applied
        suggestions = suggestion_set.suggestions
        ActiveRecord::Associations::Preloader.new(
          records: suggestions, associations: { note: { duo_created_workflow_link: :workflow } }
        ).call

        suggestions.each do |suggestion|
          next unless fix_pipeline_suggestion?(suggestion)

          ::Gitlab::InternalEvents.track_event(
            'fix_pipeline_suggestion_applied',
            user: current_user,
            project: suggestion.target_project,
            additional_properties: {
              label: suggestion.noteable.id.to_s,
              property: suggestion.id.to_s,
              value: suggestion.note_id
            }
          )
        end
      end

      def fix_pipeline_suggestion?(suggestion)
        session = suggestion.note.agent_session
        return false unless session

        consumer = ::Ai::Catalog::ItemConsumer.for_service_account(session.service_account_id).first
        consumer&.item&.foundational_flow_reference == "fix_pipeline/v1"
      end
    end
  end
end
