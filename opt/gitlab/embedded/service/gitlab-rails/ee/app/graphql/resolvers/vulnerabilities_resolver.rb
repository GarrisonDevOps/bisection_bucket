# frozen_string_literal: true

module Resolvers
  class VulnerabilitiesResolver < VulnerabilitiesBaseResolver
    include Gitlab::Utils::StrongMemoize
    include LooksAhead
    include Gitlab::InternalEventsTracking

    OWASP_IDENTIFIER_PATTERN = /\AA\d{1,2}:(2017|2021|2025)-/

    type Types::VulnerabilityType, null: true

    argument :project_id, [GraphQL::Types::ID],
      required: false,
      description: 'Filter vulnerabilities by project.'

    argument :report_type, [Types::VulnerabilityReportTypeEnum],
      required: false,
      description: 'Filter vulnerabilities by report type.'

    argument :severity, [Types::VulnerabilitySeverityEnum],
      required: false,
      description: 'Filter vulnerabilities by severity.'

    argument :state, [Types::VulnerabilityStateEnum],
      required: false,
      description: 'Filter vulnerabilities by state.'

    argument :owasp_top_ten, [Types::VulnerabilityOwaspTop10Enum],
      required: false,
      as: :owasp_top_10,
      description: 'Filter vulnerabilities by OWASP Top 10 2017 category. Wildcard value `NONE` is also supported ' \
                   'but it cannot be combined with other OWASP top 10 values.'

    argument :owasp_top_ten_2021, [::Types::Vulnerabilities::Owasp2021Top10Enum],
      required: false,
      as: :owasp_top_10_2021,
      experiment: { milestone: '18.1' },
      description: 'Filter vulnerabilities by OWASP Top 10 2021 category. Wildcard value `NONE` is also supported ' \
                   'but it cannot be combined with other OWASP top 10 2021 values. ' \
                   'To use this argument, you must have advanced search configured and advanced vulnerability management set up. ' \
                   'Not supported on Instance Security Dashboard queries.'

    argument :owasp_top_ten_2025, [::Types::Vulnerabilities::Owasp2025Top10Enum],
      required: false,
      as: :owasp_top_10_2025,
      experiment: { milestone: '19.0' },
      description: 'Filter vulnerabilities by OWASP Top 10 2025 category. Wildcard value `NONE` is also supported ' \
                   'but it cannot be combined with other OWASP top 10 2025 values. ' \
                   'To use this argument, you must have advanced search configured and advanced vulnerability management set up. ' \
                   'Not supported on Instance Security Dashboard queries.'

    argument :identifier_name, GraphQL::Types::String,
      required: false,
      description: 'Filter vulnerabilities by identifier name. ' \
                   'Ignored when applied on instance security dashboard queries.'

    argument :scanner, [GraphQL::Types::String],
      required: false,
      description: 'Filter vulnerabilities by VulnerabilityScanner.externalId.'

    argument :scanner_id, [::Types::GlobalIDType[::Vulnerabilities::Scanner]],
      required: false,
      description: 'Filter vulnerabilities by scanner ID.'

    argument :sort, Types::VulnerabilitySortEnum,
      required: false,
      default_value: 'severity_desc',
      description: 'List vulnerabilities by sort order.'

    argument :has_resolution, GraphQL::Types::Boolean,
      required: false,
      description: 'Returns only the vulnerabilities which have been resolved on default branch.'

    argument :has_ai_resolution, GraphQL::Types::Boolean,
      required: false,
      description: 'Returns only the vulnerabilities which can likely be resolved by GitLab Duo Vulnerability Resolution.'

    argument :has_issues, GraphQL::Types::Boolean,
      required: false,
      description: 'Returns only the vulnerabilities which have linked issues.'

    argument :has_merge_request, GraphQL::Types::Boolean,
      required: false,
      description: 'Returns only the vulnerabilities which have linked merge requests.'

    argument :image, [GraphQL::Types::String],
      required: false,
      description: "Filter vulnerabilities by location image. When this filter is present, "\
                   "the response only matches entries for a `reportType` "\
                   "that includes #{::Vulnerabilities::Finding::REPORT_TYPES_WITH_LOCATION_IMAGE.map { |type| "`#{type}`" }.join(', ')}."

    argument :cluster_id, [::Types::GlobalIDType[::Clusters::Cluster]],
      prepare: ->(ids, _) { Array(ids).map(&:model_id) },
      required: false,
      description: "Filter vulnerabilities by `cluster_id`. Vulnerabilities with a `reportType` "\
                   "of `cluster_image_scanning` are only included with this filter."

    argument :cluster_agent_id, [::Types::GlobalIDType[::Clusters::Agent]],
      prepare: ->(ids, _) { Array(ids).map(&:model_id) },
      required: false,
      description: "Filter vulnerabilities by `cluster_agent_id`. Vulnerabilities with a `reportType` "\
                   "of `cluster_image_scanning` are only included with this filter."

    argument :dismissal_reason, [Types::Vulnerabilities::DismissalReasonEnum],
      required: false,
      description: "Filter by dismissal reason. Only dismissed Vulnerabilities will be included with the filter."

    argument :has_remediations, GraphQL::Types::Boolean,
      required: false,
      description: 'Returns only the vulnerabilities which have remediations.'

    argument :reachability, ::Types::Sbom::ReachabilityEnum,
      required: false,
      experiment: { milestone: '18.2' },
      description: 'Filter vulnerabilities by reachability.'

    argument :validity_check, [::Types::Vulnerabilities::FindingTokenStatusStateEnum],
      required: false,
      experiment: { milestone: '18.5' },
      description: 'Filter vulnerabilities by validity check.'

    argument :policy_violations, [::Types::SecurityOrchestration::PolicyViolationsEnum],
      required: false,
      experiment: { milestone: '18.6' },
      description: 'Filter by security policy violations. ' \
        'To use this argument, you must have advanced search configured and advanced vulnerability management set up. ' \
        'Not supported on Instance Security Dashboard queries.'

    argument :policy_auto_dismissed, GraphQL::Types::Boolean,
      required: false,
      experiment: { milestone: '18.8' },
      description: 'Returns only the vulnerabilities which have been auto dismissed by security policies. ' \
        'To use this argument, you must have advanced search configured and advanced vulnerability management set up. ' \
        'Not supported on Instance Security Dashboard queries.'

    argument :false_positive, GraphQL::Types::Boolean,
      required: false,
      experiment: { milestone: '18.8' },
      description: 'Returns only the vulnerabilities with false positive flag. ' \
        'To use this argument, you must have advanced search configured and advanced vulnerability management set up. ' \
        'Not supported on Instance Security Dashboard queries.'

    argument :malware, GraphQL::Types::Boolean,
      required: false,
      description: 'Filter vulnerabilities by malware status. ' \
        'When true, returns only malware vulnerabilities (identified by GLAM-* identifiers). ' \
        'When false, returns only non-malware vulnerabilities. ' \
        'To use this argument, you must have advanced search configured and advanced vulnerability management set up. ' \
        'Not supported on Instance Security Dashboard queries. ' \
        'Cannot be combined with `trackedRefsScope: ALL_REFS` or with ' \
        '`trackedRefIds` referring to a non-default-branch ref.'

    argument :due_date_after, ::Types::DateType,
      required: false,
      experiment: { milestone: '19.6' },
      description: 'Returns only the vulnerabilities due on or after the date. ' \
        'To use this argument, you must have advanced search configured and advanced vulnerability management set up ' \
        'and the `vulnerability_due_date_filter` feature flag enabled. ' \
        'Not supported on Instance Security Dashboard queries.'

    argument :due_date_before, ::Types::DateType,
      required: false,
      experiment: { milestone: '19.6' },
      description: 'Returns only the vulnerabilities due on or before the date. ' \
        'To use this argument, you must have advanced search configured and advanced vulnerability management set up ' \
        'and the `vulnerability_due_date_filter` feature flag enabled. ' \
        'Not supported on Instance Security Dashboard queries.'

    argument :due_date_wildcard, ::Types::Vulnerabilities::DueDateWildcardIdEnum,
      required: false,
      experiment: { milestone: '19.6' },
      description: 'Filter vulnerabilities by whether they have a due date. ' \
        'Cannot be combined with `dueDateAfter` or `dueDateBefore`. ' \
        'To use this argument, you must have advanced search configured and advanced vulnerability management set up ' \
        'and the `vulnerability_due_date_filter` feature flag enabled. ' \
        'Not supported on Instance Security Dashboard queries.'

    argument :tracked_ref_ids, [::Types::GlobalIDType[::Security::ProjectTrackedContext]],
      as: :security_project_tracked_context_id,
      prepare: ->(ids, _) { Array(ids).map(&:model_id) },
      required: false,
      experiment: { milestone: '18.10' },
      description: 'Filter vulnerabilities by tracked ref IDs. ' \
               'To use this argument, you must have advanced search configured and advanced vulnerability management set up.'

    argument :tracked_refs_scope, ::Types::Security::TrackedRefScopeEnum,
      required: false,
      experiment: { milestone: '18.9' },
      description: 'Filter by tracked ref scope. ' \
        'To use this argument, you must have advanced search configured and ' \
        'advanced vulnerability management set up and the ' \
        '`vulnerabilities_across_contexts` feature flag enabled.'

    argument :security_attributes_filters, [Types::Security::AttributeFilterInputType],
      required: false,
      experiment: { milestone: '19.5' },
      validates: { length: { maximum: VulnerabilityFilterable::MAX_SECURITY_ATTRIBUTE_FILTERS } },
      description: 'Filter vulnerabilities by the security attributes of their projects. ' \
        "Up to #{VulnerabilityFilterable::MAX_SECURITY_ATTRIBUTE_FILTERS} filters. " \
        'To use this argument, you must have advanced search configured and advanced vulnerability management set up. ' \
        'Available on group queries only, when the `vulnerability_report_security_attributes_filter` ' \
        'feature flag is enabled.'

    argument :security_boundary, [::Types::Vulnerabilities::SecurityBoundaryFilterEnum],
      required: false,
      experiment: { milestone: '19.6' },
      validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
      description: 'Filter vulnerabilities by the security boundary of their component. ' \
        "#{VulnerabilityFilterable::SECURITY_CONTEXT_FILTER_DESCRIPTION}"

    argument :authentication, [::Types::Vulnerabilities::AuthenticationFilterEnum],
      required: false,
      experiment: { milestone: '19.6' },
      validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
      description: 'Filter vulnerabilities by whether their component requires authentication. ' \
        "#{VulnerabilityFilterable::SECURITY_CONTEXT_FILTER_DESCRIPTION}"

    argument :authorization, [::Types::Vulnerabilities::AuthorizationFilterEnum],
      required: false,
      experiment: { milestone: '19.6' },
      validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
      description: 'Filter vulnerabilities by whether their component requires elevated privileges. ' \
        "#{VulnerabilityFilterable::SECURITY_CONTEXT_FILTER_DESCRIPTION}"

    argument :sensitive_data, [::Types::Vulnerabilities::SensitiveDataFilterEnum],
      required: false,
      experiment: { milestone: '19.6' },
      validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
      description: 'Filter vulnerabilities by whether their component handles sensitive data. ' \
        "#{VulnerabilityFilterable::SECURITY_CONTEXT_FILTER_DESCRIPTION}"

    def resolve_with_lookahead(**args)
      return Vulnerability.none unless vulnerable&.feature_available?(:security_dashboard)

      validate_filters(args)
      set_data_source(args)
      track_events(args)

      args[:scanner_id] = resolve_gids(args[:scanner_id], ::Vulnerabilities::Scanner) if args[:scanner_id]

      disabled_filters = context.response_extensions["disabled_filters"] ||= []
      disabled_filters << :identifier_name unless search_by_identifier_allowed_on_db?(vulnerable: vulnerable)

      fetch_vulnerabilities(args)
    end

    def unconditional_includes
      if using_elasticsearch # With ES we directly return Vulnerability records
        return [
          { project: [:namespace, :group, :route] },
          { findings: [:scanner, :identifiers, :primary_identifier] },
          :vulnerability_read
        ]
      end

      # project: [:route] is added in the as_vulnerabilities method.
      [
        { vulnerability:
          [
            { project: [:namespace, :group] },
            { findings: [:scanner, :identifiers, :primary_identifier] },
            :vulnerability_read
          ] }
      ]
    end

    def preloads
      base_associations = {
        has_remediations: { findings: :remediations },
        merge_request: :merge_request_links,
        merge_requests: :merge_request_links,
        state_comment: :state_transitions,
        state_transitions: :state_transitions,
        false_positive: { findings: :vulnerability_flags },
        representation_information: :representation_information,
        details: :representation_information,
        location: [{ findings: :latest_finding_pipeline }, :representation_information],
        links: { findings: :finding_links },
        external_issue_links: :external_issue_links,
        primary_identifier: { findings: :primary_identifier },
        initial_detected_pipeline: { findings: :initial_finding_pipeline },
        latest_detected_pipeline: { findings: :latest_finding_pipeline },
        policy_auto_dismissed: [:dismissed_by, :group],
        tracked_ref: { vulnerability_read: :tracked_context },
        due_date: { findings: :finding_due_date },
        duo_sast_vr_workflow_enabled: { project: :project_setting }
      }

      return base_associations if using_elasticsearch # With ES we directly return Vulnerability records

      wrap_with_vulnerability(base_associations)
    end

    private

    attr_reader :using_elasticsearch

    def set_data_source(args)
      @using_elasticsearch = use_elasticsearch?(args)
    end

    def fetch_vulnerabilities(args)
      if using_elasticsearch
        vulnerabilities_from_es(args)
      else
        finder_params = args.merge(before_severity: before_severity, after_severity: after_severity)

        vulnerabilities(finder_params)
      end
    end

    def vulnerabilities(finder_params)
      apply_lookahead(::Security::VulnerabilityReadsFinder.new(vulnerable, finder_params).execute.as_vulnerabilities)
    end

    def vulnerabilities_from_es(finder_params)
      finder_params = with_security_attributes_as_project_ids(finder_params)

      apply_lookahead(::Search::AdvancedFinders::Security::Vulnerability::SearchFinder.new(vulnerable, finder_params).execute)
    end

    def wrap_with_vulnerability(associations)
      associations.transform_values do |association|
        { vulnerability: association }
      end
    end

    def after_severity
      severity_from_cursor(:after)
    end

    def before_severity
      severity_from_cursor(:before)
    end

    def severity_from_cursor(cursor)
      cursor_value = current_arguments && current_arguments[cursor]

      return unless cursor_value

      decoded_cursor = Base64.urlsafe_decode64(cursor_value)

      Gitlab::Json.parse(decoded_cursor)['severity']
    rescue ArgumentError, JSON::ParserError
    end

    def current_arguments
      context[:current_arguments]
    end

    def track_events(args)
      track_internal_event(
        "called_vulnerability_api",
        user: current_user,
        project: vulnerable.is_a?(::Project) ? vulnerable : nil,
        namespace: vulnerable.is_a?(::Group) ? vulnerable : nil,
        additional_properties: {
          label: 'graphql',
          value: using_elasticsearch ? 1 : 0
        }
      )

      track_event_filter_ai_fp(args[:false_positive]) if args.key?(:false_positive)
      {
        owasp_top_10: "group_by_owasp_top_10_in_vulnerability_report",
        owasp_top_10_2021: "group_by_owasp_top_10_2021_in_vulnerability_report",
        owasp_top_10_2025: "group_by_owasp_top_10_2025_in_vulnerability_report"
      }.each do |arg_key, event_name|
        track_event_group_by_owasp(event_name) if args[arg_key].present?
      end

      track_event_filter_identifier(args[:identifier_name]) if args[:identifier_name].present?
    end

    def track_event_group_by_owasp(event_name)
      track_internal_event(
        event_name,
        user: current_user,
        project: vulnerable.is_a?(::Project) ? vulnerable : nil,
        namespace: vulnerable.is_a?(::Group) ? vulnerable : nil,
        additional_properties: {
          label: 'graphql',
          value: 1
        }
      )
    end

    def track_event_filter_identifier(identifier_name)
      return unless identifier_name.match?(OWASP_IDENTIFIER_PATTERN)

      track_internal_event(
        "filter_identifier_in_vulnerability_report",
        user: current_user,
        project: vulnerable.is_a?(::Project) ? vulnerable : nil,
        namespace: vulnerable.is_a?(::Group) ? vulnerable : nil,
        additional_properties: {
          label: 'graphql',
          property: identifier_name
        }
      )
    end

    def track_event_filter_ai_fp(false_positive_arg)
      track_internal_event(
        "filter_ai_fp",
        user: current_user,
        project: vulnerable.is_a?(::Project) ? vulnerable : nil,
        namespace: vulnerable.is_a?(::Group) ? vulnerable : nil,
        additional_properties: {
          label: 'graphql',
          value: false_positive_arg ? 1 : 0
        }
      )
    end
  end
end
