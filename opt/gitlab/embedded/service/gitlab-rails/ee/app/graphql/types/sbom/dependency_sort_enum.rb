# frozen_string_literal: true

module Types
  module Sbom
    class DependencySortEnum < BaseEnum
      graphql_name 'DependencySort'
      description 'Values for sorting dependencies'

      value 'NAME_DESC', 'Name by descending order.', value: :name_desc
      value 'NAME_ASC', 'Name by ascending order.', value: :name_asc
      value 'PACKAGER_DESC', 'Packager by descending order.', value: :packager_desc
      value 'PACKAGER_ASC', 'Packager by ascending order.', value: :packager_asc
      value 'SEVERITY_DESC', 'Severity by descending order.', value: :severity_desc
      value 'SEVERITY_ASC', 'Severity by ascending order.', value: :severity_asc
      value 'LICENSE_ASC', 'License by ascending order.', value: :license_asc
      value 'LICENSE_DESC', 'License by descending order.', value: :license_desc
    end
  end
end
