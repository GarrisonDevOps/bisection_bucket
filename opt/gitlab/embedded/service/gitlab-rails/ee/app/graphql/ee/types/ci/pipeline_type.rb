# frozen_string_literal: true

module EE
  module Types
    module Ci
      module PipelineType
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :retryable
        def retryable
          return false if object.completed_merge_train_pipeline?

          super
        end

        prepended do
          field :compute_minutes,
            GraphQL::Types::Float,
            null: true,
            method: :total_ci_minutes_consumed,
            description: "Total minutes consumed by the pipeline."

          field :security_report_summary,
            ::Types::SecurityReportSummaryType,
            null: true,
            extras: [:lookahead],
            description: 'Vulnerability and scanned resource counts for each security scanner of the pipeline.',
            resolver: ::Resolvers::SecurityReportSummaryResolver

          # rubocop:disable Layout/LineLength -- otherwise description is creating unnecessary spaces.
          field :security_report_findings,
            ::Types::PipelineSecurityReportFindingType.connection_type,
            null: true,
            description: 'Vulnerability findings reported on the pipeline. By default all the states except dismissed are included in the response.',
            scopes: [:api, :read_api, :ai_workflows],
            # Although we're not paginating an Array here we're using this
            # connection extension because it leaves the pagination
            # arguments available for the resolver.  Otherwise they are
            # removed by the framework.
            connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
            resolver: ::Resolvers::PipelineSecurityReportFindingsResolver
          # rubocop:enable Layout/LineLength

          field :security_report_finding,
            ::Types::PipelineSecurityReportFindingType,
            null: true,
            description: 'Vulnerability finding reported on the pipeline.',
            scopes: [:api, :read_api, :ai_workflows],
            resolver: ::Resolvers::SecurityReport::FindingResolver

          field :enabled_security_scans,
            ::Types::Security::EnabledScansType,
            description: 'Security scans present in the pipeline and its descendents for each report type',
            resolver: ::Resolvers::Security::EnabledScansResolver,
            experiment: { milestone: '18.3' }

          field :enabled_partial_security_scans,
            ::Types::Security::EnabledScansType,
            description: 'Partial scans present in the pipeline and its descendents for each report type',
            resolver: ::Resolvers::Security::EnabledPartialScansResolver,
            experiment: { milestone: '18.3' }

          field :code_quality_reports,
            ::Types::Ci::CodeQualityDegradationType.connection_type,
            null: true,
            description: 'Code Quality degradations reported on the pipeline.'

          field :code_quality_report_summary,
            ::Types::Ci::CodeQualityReportSummaryType,
            null: true,
            description: 'Code Quality report summary for a pipeline.'

          field :dast_profile,
            ::Types::Dast::ProfileType,
            null: true,
            description: 'DAST profile associated with the pipeline.'

          field :duo_workflows,
            ::Types::Ai::DuoWorkflows::WorkflowType.connection_type,
            experiment: { milestone: '19.3' },
            null: true,
            description: 'Duo Workflow sessions associated with the pipeline.',
            resolver: ::Resolvers::Ai::DuoWorkflows::PipelineWorkflowsResolver

          field :duo_workflow_links,
            resolver: ::Resolvers::Ai::DuoWorkflows::PipelineDuoWorkflowLinksResolver,
            description: 'GitLab Duo Agent Platform sessions linked to the pipeline.' do
              extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
            end

          field :troubleshoot_job_with_ai, GraphQL::Types::Boolean, null: false,
            description: "If the user can troubleshoot jobs of a pipeline."

          def troubleshoot_job_with_ai
            return false unless current_user

            Ability.allowed?(current_user, :troubleshoot_job_with_ai, pipeline)
          end

          def code_quality_reports
            pipeline.accessible_codequality_reports(current_user).sort_degradations!.values.presence
          end

          def code_quality_report_summary
            pipeline.accessible_codequality_reports(current_user).code_quality_report_summary
          end

          def dast_profile
            pipeline.dast_profile
          end
        end
      end
    end
  end
end
