# frozen_string_literal: true

module Sbom
  class VulnerabilitiesCreatedEvent < ::Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'properties' => {
          'findings' => {
            'type' => 'array',
            'items' => {
              'type' => 'object',
              'properties' => {
                'uuid' => {
                  'type' => 'string'
                },
                'project_id' => {
                  'type' => 'integer'
                },
                'pipeline_id' => {
                  'type' => 'integer'
                },
                'vulnerability_id' => {
                  'type' => 'integer'
                },
                'package_name' => {
                  'type' => 'string'
                },
                'package_version' => {
                  'type' => 'string'
                },
                'purl_type' => {
                  'type' => 'string'
                }
              },
              'required' => %w[uuid project_id vulnerability_id package_name package_version purl_type]
            }
          }
        },
        'required' => %w[findings]
      }
    end
  end
end
