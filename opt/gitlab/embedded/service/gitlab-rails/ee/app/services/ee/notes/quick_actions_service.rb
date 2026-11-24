# frozen_string_literal: true

module EE
  module Notes
    module QuickActionsService
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      prepended do
        EE_SUPPORTED_NOTEABLES = %w[Epic].freeze
        EE::Notes::QuickActionsService.private_constant :EE_SUPPORTED_NOTEABLES
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        override :supported_noteables
        def supported_noteables
          super + EE_SUPPORTED_NOTEABLES
        end
      end

      def noteable_update_service(note, update_params)
        return super unless note.for_epic?

        ::WorkItems::LegacyEpics::UpdateService.new(
          group: note.resource_parent, current_user: current_user, params: update_params
        )
      end

      override :execute_triggers
      def execute_triggers(note, params)
        super

        execute_amazon_q_trigger(note, params)
      end

      def execute_amazon_q_trigger(note, params)
        return unless params[:amazon_q]

        q_params = params.delete(:amazon_q)

        ::Ai::AmazonQ::AmazonQTriggerService.new(
          user: current_user,
          command: q_params[:command],
          input: q_params[:input],
          source: q_params[:source],
          note: note,
          discussion_id: q_params[:discussion_id]
        ).execute
      end
    end
  end
end
