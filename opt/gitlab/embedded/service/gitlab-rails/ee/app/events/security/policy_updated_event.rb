# frozen_string_literal: true

module Security
  class PolicyUpdatedEvent < ::Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'properties' => {
          'security_policy_id' => { 'type' => 'integer' },
          'diff' => {
            'type' => 'object',
            'patternProperties' => {
              '^.*$' => {
                'type' => 'object',
                'properties' => {
                  'from' => {
                    'type' => %w[string number boolean object array null]
                  },
                  'to' => {
                    'type' => %w[string number boolean object array null]
                  }
                },
                'required' => %w[from to]
              }
            }
          },
          'rules_diff' => {
            'type' => 'object',
            'properties' => {
              'created' => {
                'type' => 'array',
                'items' => {
                  'type' => 'object'
                }
              },
              'updated' => {
                'type' => 'array',
                'items' => {
                  'type' => 'object',
                  'properties' => {
                    'id' => {
                      'type' => 'integer'
                    },
                    'from' => {
                      'type' => 'object'
                    },
                    'to' => {
                      'type' => %w[object null]
                    }
                  },
                  'required' => %w[from to id]
                }
              },
              'deleted' => {
                'type' => 'array',
                'items' => {
                  'type' => 'object',
                  'properties' => {
                    'id' => {
                      'type' => 'integer'
                    },
                    'from' => {
                      'type' => 'object'
                    },
                    'to' => {
                      'type' => %w[object null]
                    }
                  },
                  'required' => %w[from to id]
                }
              }
            },
            'required' => %w[created updated deleted]
          }
        },
        'required' => %w[security_policy_id diff rules_diff]
      }
    end
  end
end
