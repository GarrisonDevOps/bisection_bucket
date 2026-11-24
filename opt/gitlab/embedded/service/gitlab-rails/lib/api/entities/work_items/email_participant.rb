# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      class EmailParticipant < Grape::Entity
        include ConditionalExposureHelpers

        expose :id,
          documentation: { type: 'Integer', format: 'int64', example: 42, desc: 'ID of the email participant.' }

        # IssueEmailParticipantPresenter checks read_external_emails on the work item's project, so for work items
        # in groups (no project) the email is always obfuscated.
        expose :email,
          documentation: {
            type: 'String', example: 'us**@ex*****.com',
            desc: 'Email address of the participant. Obfuscated unless the current user has at least the ' \
              "Reporter role in the work item's project. Always obfuscated for work items in groups."
          } do |participant, options|
          IssueEmailParticipantPresenter.new(
            participant, current_user: options[:current_user]
          ).email
        end

        expose_field :created_at,
          documentation: {
            type: 'DateTime', example: '2024-01-15T10:00:00.000Z',
            desc: 'Time the email participant was added to the work item.'
          }

        expose_field :updated_at,
          documentation: {
            type: 'DateTime', example: '2024-01-15T10:00:00.000Z', desc: 'Time the email participant was last updated.'
          }
      end
    end
  end
end
