# frozen_string_literal: true

module API
  module Entities
    class Membership < Grape::Entity
      expose :source_id
      expose :source_name do |member|
        member.source.name
      end
      expose :source_type
      expose :access_level,
        documentation: {
          type: 'String',
          desc: 'Access level of the user. Possible values: `0` (no access), `5` (minimal access), `10` (guest), ' \
            '`15` (planner), `20` (reporter), `25` (security manager), `30` (developer), `40` (maintainer), ' \
            'and `50` (owner).'
        }
    end
  end
end
