# frozen_string_literal: true

module Types
  module Ci
    class MergeTrainEnforcementEnum < BaseEnum
      graphql_name 'MergeTrainEnforcement'
      description 'Merge train enforcement levels for a project.'

      value 'ALLOW_BYPASS', value: 'allow_bypass',
        description: 'Users with permission to merge can bypass the merge train through the UI or API.'
      value 'ENFORCE_FOR_ALL_USERS', value: 'enforce_for_all_users',
        description: 'All merge requests must go through the merge train. The merge train cannot be bypassed.'
      value 'ENFORCE_WITH_OWNER_OVERRIDE', value: 'enforce_with_owner_override',
        description: 'All merge requests must go through the merge train. ' \
          'Owners and administrators can bypass the merge train for individual merge requests.'
    end
  end
end
