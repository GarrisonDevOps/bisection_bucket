# frozen_string_literal: true

module Types
  module Security
    class TrackedRefScopeEnum < BaseEnum
      graphql_name 'SecurityTrackedRefScope'
      description 'Return vulnerabilities scoped to certain types of refs.'

      value 'DEFAULT_BRANCHES', 'Returns only results on default branches.', value: :default_branches
      value 'ALL_REFS', 'Returns results on all tracked refs, including refs that are not default branches.',
        value: :all_refs
    end
  end
end
