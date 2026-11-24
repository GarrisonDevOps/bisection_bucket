# frozen_string_literal: true

module API
  module Entities
    class UserPreferences < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :user_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :view_diffs_file_by_file, documentation: { type: 'Boolean' }
      expose :show_whitespace_in_diffs, documentation: { type: 'Boolean' }
      expose :pass_user_identities_to_ci_jwt, documentation: { type: 'Boolean' }
      expose :policy_advanced_editor, documentation: { type: 'Boolean' }
      expose :emoji_skin_tone, documentation: { type: 'Integer', example: 0 }

      # The mobile push working hours. Always present on a server with this
      # code; an older server returns none of them, which is how the mobile
      # app learns the instance cannot do this.
      expose :mobile_push_working_hours_enabled, documentation: { type: 'Boolean', example: true }
      expose :mobile_push_working_hours_start, documentation: { type: 'Integer', example: 540 }
      expose :mobile_push_working_hours_end, documentation: { type: 'Integer', example: 1020 }
      expose :mobile_push_working_days,
        documentation: { type: 'String', is_array: true, example: %w[monday tuesday wednesday thursday friday] }
      expose :mobile_push_working_hours_time_zone, documentation: { type: 'String', example: 'Europe/Berlin' }
    end
  end
end
