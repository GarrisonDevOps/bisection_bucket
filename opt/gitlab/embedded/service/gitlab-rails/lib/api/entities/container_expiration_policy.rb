# frozen_string_literal: true

module API
  module Entities
    class ContainerExpirationPolicy < Grape::Entity
      expose :cadence, documentation: {
        type: 'String', example: '7d', desc: 'How often the cleanup policy runs, such as `1d` or `7d`.'
      }
      expose :enabled, documentation: { type: 'Boolean', desc: 'If `true`, the cleanup policy is enabled.' }
      expose :keep_n, documentation: { type: 'Integer', example: 10, desc: 'Number of tags to keep for each image.' }
      expose :older_than, documentation: {
        type: 'String', example: '90d', desc: 'Tags older than this value are removed, such as `90d`.'
      }
      expose :name_regex, documentation: {
        type: 'String', example: '.*', desc: 'Regular expression of tag names to remove.'
      }
      expose :name_regex_keep, documentation: { type: 'String', desc: 'Regular expression of tag names to keep.' }
      expose :next_run_at, documentation: {
        type: 'DateTime', desc: 'Date and time of the next scheduled policy run.'
      }
    end
  end
end
