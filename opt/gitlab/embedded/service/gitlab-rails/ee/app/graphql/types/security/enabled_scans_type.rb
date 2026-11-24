# frozen_string_literal: true

module Types
  module Security
    class EnabledScansType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Object is a hash
      graphql_name 'EnabledSecurityScans'

      description 'Types of scans enabled on a merge request'

      field :ready, GraphQL::Types::Boolean,
        null: false,
        description: 'Returns `true` when report processing has been completed.'

      ::Security::Scan.scan_types.each_key do |scan_type|
        field scan_type.to_sym,
          type: ::GraphQL::Types::Boolean,
          null: false,
          description: "`true` if there is a #{scan_type.humanize} scan in the pipeline"
      end
    end
  end
end
