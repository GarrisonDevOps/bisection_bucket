# frozen_string_literal: true

module Resolvers
  module SecurityReport
    class FindingReportsComparerResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::Security::FindingReportsComparerType, null: true

      authorize :read_security_resource
      authorizes_object!

      authorize_granular_token permissions: :read_vulnerability, boundary: :project, boundary_type: :project

      argument :report_type, Types::Security::ComparableReportTypeEnum,
        required: true,
        description: 'Filter vulnerability findings by report type.'

      argument :scan_mode, Types::Security::ScanModeEnum,
        required: false,
        description: 'Filter results by scan mode.'

      def resolve(**params)
        # Necessary to use project as actor in FF check
        context[:project] = object.project

        ::Security::MergeRequestSecurityReportGenerationService.execute(object, params)
      end
    end
  end
end
