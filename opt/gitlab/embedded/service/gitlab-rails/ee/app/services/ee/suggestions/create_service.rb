# frozen_string_literal: true

module EE
  module Suggestions # rubocop:disable Gitlab/BoundedContexts -- EE override of CE Suggestions::CreateService
    module CreateService
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        super.tap do
          track_fix_pipeline_suggestions_posted
        end
      end

      private

      def track_fix_pipeline_suggestions_posted
        service_account = note.agent_session&.service_account
        return unless service_account

        consumer = ::Ai::Catalog::ItemConsumer.for_service_account(service_account.id).first
        return unless consumer&.item&.foundational_flow_reference == "fix_pipeline/v1"

        note.suggestions.reset.each do |suggestion|
          ::Gitlab::InternalEvents.track_event(
            'fix_pipeline_suggestion_posted',
            user: service_account,
            project: note.noteable.target_project,
            additional_properties: {
              label: note.noteable_id.to_s,
              property: suggestion.id.to_s,
              value: note.id
            }
          )
        end
      end
    end
  end
end
