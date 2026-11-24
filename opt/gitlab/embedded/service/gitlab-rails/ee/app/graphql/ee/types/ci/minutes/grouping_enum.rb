# frozen_string_literal: true

# rubocop:disable Gitlab/EeOnlyClass -- This is only used in GitLab dedicated that comes under ultimate tier only.
module EE
  module Types
    module Ci
      module Minutes
        class GroupingEnum < ::Types::BaseEnum
          graphql_name 'GroupingEnum'
          description 'Values for grouping compute usage data.'

          value 'INSTANCE_AGGREGATE', 'Aggregate usage data across all namespaces in the instance.'
          value 'PER_ROOT_NAMESPACE', 'Group data by individual root namespace.'
        end
      end
    end
  end
end
# rubocop:enable Gitlab/EeOnlyClass
