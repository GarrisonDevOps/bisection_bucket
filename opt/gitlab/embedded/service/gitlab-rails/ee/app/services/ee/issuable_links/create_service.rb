# frozen_string_literal: true

module EE
  module IssuableLinks
    module CreateService
      extend ::Gitlab::Utils::Override

      private

      override :link_issuables
      def link_issuables(objects)
        # it is important that this is not called after relate_issuables, as it relinks epic to the issuable
        # relate_issuables is called during the `super` portion of this method
        # see EpicLinks::EpicIssues#relate_issuables
        affected_epics = affected_epics(objects)

        super.tap do
          Epics::UpdateDatesService.new(affected_epics).execute if update_epic_dates?(affected_epics)
        end
      end

      def affected_epics(_issues)
        []
      end

      override :set_link_type
      def set_link_type(link)
        return unless params[:link_type].present?

        # `blocked_by` links are treated as `blocks` links where source and target is swapped.
        if params[:link_type] == ::IssuableLink::TYPE_IS_BLOCKED_BY
          link.source, link.target = link.target, link.source
          link.link_type = ::IssuableLink::TYPE_BLOCKS
        else
          link.link_type = params[:link_type]
        end
      end

      override :create_notes
      def create_notes(issuable_link)
        if issuable_link.blocks?
          ::SystemNoteService.block_issuable(issuable_link.source, issuable_link.target, current_user)
          ::SystemNoteService.blocked_by_issuable(issuable_link.target, issuable_link.source, current_user)
        else
          super
        end
      end

      def update_epic_dates?(affected_epics)
        return false if params[:skip_epic_dates_update]
        return false if affected_epics.empty?

        true
      end
    end
  end
end
