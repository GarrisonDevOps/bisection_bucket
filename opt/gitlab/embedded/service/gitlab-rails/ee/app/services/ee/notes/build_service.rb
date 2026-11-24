# frozen_string_literal: true

module EE
  module Notes
    module BuildService
      extend ::Gitlab::Utils::Override

      private

      override :new_note
      def new_note(params, discussion)
        workflow_id = params.delete(:workflow_id)

        note = super

        handle_duo_metadata(note, workflow_id)

        note
      end

      def handle_duo_metadata(note, workflow_id)
        return if workflow_id.blank?

        namespace_id = project&.namespace_id
        return if namespace_id.blank?

        note.build_duo_metadata(workflow_id: workflow_id, namespace_id: namespace_id)
      end
    end
  end
end
