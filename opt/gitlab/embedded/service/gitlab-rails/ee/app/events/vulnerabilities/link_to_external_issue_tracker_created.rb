# frozen_string_literal: true

module Vulnerabilities
  class LinkToExternalIssueTrackerCreated < Gitlab::EventStore::Event
    attr_accessor :project # TODO: remove with feature flag

    def schema
      {
        'type' => 'object',
        'required' => ['vulnerability_id'],
        'properties' => {
          'vulnerability_id' => { 'type' => 'integer' }
        }
      }
    end
  end
end
