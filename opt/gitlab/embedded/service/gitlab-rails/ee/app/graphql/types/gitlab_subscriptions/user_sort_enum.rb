# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class UserSortEnum < BaseEnum
      graphql_name 'GitlabSubscriptionsUserSort'
      description 'Values for sorting users'

      value 'ID_ASC', 'Id by ascending order.', value: :id_asc
      value 'ID_DESC', 'Id by descending order.', value: :id_desc
      value 'NAME_ASC', 'Name by ascending order.', value: :name_asc
      value 'NAME_DESC', 'Name by descending order.', value: :name_desc
      value 'LAST_ACTIVITY_ON_ASC', 'Last activity by ascending order.', value: :last_activity_on_asc
      value 'LAST_ACTIVITY_ON_DESC', 'Last activity by descending order.', value: :last_activity_on_desc
    end
  end
end
