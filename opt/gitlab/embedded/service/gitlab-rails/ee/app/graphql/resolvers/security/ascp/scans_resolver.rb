# frozen_string_literal: true

module Resolvers
  module Security
    module Ascp
      class ScansResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type Types::Security::Ascp::ScanType.connection_type, null: true

        authorize :read_ascp_scan
        authorizes_object!

        description 'Find ASCP scans for a project.'

        argument :scan_type, Types::Security::Ascp::ScanTypeEnum,
          required: false,
          description: 'Filter by scan type.'

        def resolve(**args)
          ::Security::Ascp::ScansFinder.new(
            project: object,
            params: args
          ).execute
        end
      end
    end
  end
end
