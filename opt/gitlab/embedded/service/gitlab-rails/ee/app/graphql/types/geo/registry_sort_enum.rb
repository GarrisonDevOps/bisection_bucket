# frozen_string_literal: true

module Types
  module Geo
    class RegistrySortEnum < BaseEnum
      graphql_name 'GeoRegistrySort'
      description 'Values for sorting Geo registries'

      value 'ID_ASC', description: 'ID by ascending order.', value: :id_asc
      value 'ID_DESC', description: 'ID by descending order.', value: :id_desc
      value 'VERIFIED_AT_ASC', description: 'Latest verification date by ascending order.', value: :verified_at_asc
      value 'VERIFIED_AT_DESC', description: 'Latest verification date by descending order.', value: :verified_at_desc
      value 'LAST_SYNCED_AT_ASC', description: 'Latest sync date by ascending order.', value: :last_synced_at_asc
      value 'LAST_SYNCED_AT_DESC', description: 'Latest sync date by descending order.', value: :last_synced_at_desc
    end
  end
end
