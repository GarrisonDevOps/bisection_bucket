# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Description < Grape::Entity
          expose :description,
            documentation: {
              type: 'String', example: 'Repellendus impedit et vel velit dignissimos.',
              desc: 'Description of the work item in Markdown. Null or empty if the work item has no description.'
            },
            expose_nil: true
          expose :description_html,
            documentation: {
              type: 'String', example: '<p>Repellendus impedit et vel velit dignissimos.</p>',
              desc: 'Description of the work item rendered as HTML. Empty if the work item has no description.'
            },
            expose_nil: true do |feature, options|
            MarkupHelper.markdown_field(feature.work_item, :description, current_user: options[:current_user])
          end
          expose :edited?, as: :edited,
            documentation: {
              type: 'Boolean', example: false,
              desc: 'Whether the description was edited since the work item was created.'
            }
          expose :last_edited_at,
            documentation: {
              type: 'DateTime', example: '2022-11-15T08:30:55.232Z',
              desc: 'Time the description was last edited. Null if it was never edited.'
            },
            expose_nil: true
          expose :last_edited_by, using: ::API::Entities::UserBasic,
            documentation: {
              type: 'Entities::UserBasic',
              desc: 'User who last edited the description. Null if the description was not edited. ' \
                'A ghost user if the editor was deleted.'
            },
            expose_nil: true
          expose :task_completion_status,
            using: ::API::Entities::TaskCompletionStatus,
            documentation: {
              type: 'Entities::TaskCompletionStatus',
              desc: 'Number of task list items in the description, and how many of them are completed.'
            }
        end
      end
    end
  end
end
