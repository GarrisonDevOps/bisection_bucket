# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      class LinkedWorkItem < ::API::Entities::WorkItemBasic
        expose :issue_link_id, as: :link_id,
          documentation: { type: 'Integer', example: 1, desc: 'ID of the link between the two work items.' }
        # Issue#issue_link_type inverts the stored type when the requested work item is the link's target, so a
        # stored `blocks` link reads as `is_blocked_by` from the blocked item's side.
        expose :issue_link_type, as: :link_type,
          documentation: {
            type: 'String',
            example: 'relates_to',
            values: ::WorkItems::RelatedWorkItemLink.available_link_types,
            desc: 'Type of link, from the side of the work item in the request. ' \
              'For example, `blocks` means the requested work item blocks this linked item.'
          }
        expose :issue_link_created_at, as: :link_created_at,
          documentation: { type: 'DateTime', example: '2022-01-31T15:10:44.988Z', desc: 'Time the link was created.' }
        expose :issue_link_updated_at, as: :link_updated_at,
          documentation: {
            type: 'DateTime', example: '2022-01-31T15:10:44.988Z', desc: 'Time the link was last updated.'
          }
      end
    end
  end
end
