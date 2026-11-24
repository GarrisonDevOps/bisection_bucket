# frozen_string_literal: true

module Types
  module Cd
    class ApplicationLinkTypeEnum < BaseEnum
      graphql_name 'CdApplicationLinkType'
      description 'Type of a continuous deployment application link.'

      # Display labels the frontend renders for each type. The enum values stay
      # in sync with the model; the frontend owns the runtime label/icon mapping.
      LABELS = {
        'runbook' => 'Runbook',
        'dashboard' => 'Dashboard',
        'docs' => 'Docs',
        'repository' => 'Repository',
        'chat' => 'Chat / Slack',
        'issue_tracker' => 'Issue tracker',
        'on_call' => 'On-call rotation',
        'change_request' => 'Change / CR system',
        'other' => 'Other'
      }.freeze

      ::Cd::ApplicationLink.link_types.each_key do |link_type|
        value link_type.upcase, value: link_type, description: "#{LABELS.fetch(link_type)} link."
      end
    end
  end
end
