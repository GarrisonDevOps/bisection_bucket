# frozen_string_literal: true

module Gitlab
  module Security
    module Parsers
      class Sarif
        SecurityReportParserError = Class.new(::Gitlab::Ci::Parsers::ParserError)

        LEVEL_TO_SEVERITY = {
          'error' => 'high',
          'warning' => 'medium',
          'note' => 'low',
          'none' => 'info'
        }.freeze

        DEFAULT_SEVERITY = 'medium'

        SECONDARY_IDENTIFIER_TYPES = %w[cwe cve].freeze

        # When the fraction of skipped results exceeds this threshold the parser
        # treats the scan as a hard failure rather than a partial success. The
        # value (50 %) was agreed on in:
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/452042#note_3268134348
        INGESTION_FAILURE_THRESHOLD = 0.5

        # Caps the number of tool runs processed per SARIF artifact.
        # Without a bound, an artifact could exhaust the security_scans unique index
        # slots, flood the findings table, and cause Sidekiq worker timeouts.
        # 20 covers every real-world multi-tool scenario we are aware of.
        MAX_RUNS = 20

        MAX_RESULTS_PER_RUN = 5_000
        MAX_RULES_PER_RUN = 25_000
        MAX_TAGS_PER_RULE = 10

        MAX_CHARS = {
          rule_name: 255,
          short_description: 1_024,
          full_description: 2_048,
          message: 2_048,
          help_uri: 2_048
        }.freeze

        SKIP_REASON_LABELS = {
          missing_rule_id: 'missing ruleId',
          missing_location: 'missing physicalLocation',
          nil_uuid_components: 'nil UUID components'
        }.freeze

        def self.parse!(json_data, report, validate: false, **)
          new(json_data, report, validate: validate).parse!
        end

        def initialize(json_data, report, validate: false, **)
          @json_data = json_data
          @report    = report
          @project   = report.project
          @validate  = validate
        end

        def parse!
          sanitize_json_data

          return [report] unless valid?
          raise SecurityReportParserError, "Invalid report format" unless report_data.is_a?(Hash)

          @total_results = 0
          @added_findings = 0
          @skip_reason_counts = Hash.new(0)
          @truncated_counts = Hash.new(0)
          @ignored_help_uris = 0

          runs = Array(report_data['runs'])
          if runs.size > MAX_RUNS
            report.add_error('Ingestion',
              "SARIF file contains #{runs.size} runs, which exceeds the maximum of #{MAX_RUNS}.")
            return [report]
          end

          typed_reports = runs.flat_map { |run| process_run(run) }

          add_truncation_warnings

          return [report] if typed_reports.empty?

          copy_warnings_to(typed_reports)
          add_ingestion_feedback(typed_reports) if @added_findings < @total_results

          typed_reports
        rescue JSON::ParserError
          raise SecurityReportParserError, 'JSON parsing failed'
        rescue SecurityReportParserError
          raise
        rescue StandardError
          raise SecurityReportParserError, 'SARIF security report parsing failed'
        end

        private

        attr_reader :json_data, :report, :validate, :project

        # PostgreSQL cannot store texts containing the unicode null character (U+0000).
        # The regex matches unescaped \u0000 sequences in the raw JSON string and
        # escapes them so Oj parses them as the literal string "\u0000" rather than
        # the null byte. This is identical to the sanitisation in Common#sanitize_json_data.
        def sanitize_json_data
          return unless json_data.gsub!(/(?<!\\)(?:\\\\)*\\u0000/, '\\\\\u0000')

          report.add_warning('Parsing',
            'Report artifact contained unicode null characters which are escaped during ingestion.')
        end

        def valid?
          return true unless validate

          validator = ::Gitlab::Security::Parsers::Validators::SarifSchemaValidator.new(report_data)
          validator.errors.each { |error| report.add_error('Schema', error) }
          validator.valid?
        end

        def report_data
          @report_data ||= Gitlab::Json.safe_parse(json_data)
        end

        def process_run(run)
          driver = run.dig('tool', 'driver') || {}
          rules = index_rules(driver['rules'])
          scanner = build_scanner(driver)
          orig_uris = run['originalUriBaseIds'] || {}
          results = truncate(Array(run['results']), MAX_RESULTS_PER_RUN, 'results')

          buckets = {}
          # Both values below are derived from the rule alone, and one rule commonly
          # fires for many results, so they are computed once per rule id.
          semantics = {}

          results.each do |result|
            next if suppressed?(result)

            @total_results += 1

            rule_id = rule_id_for(result)
            rule = rules[rule_id] || {}

            semantic_ids, inferred = semantics[rule_id] ||= begin
              ids = IdentifierExtractor.semantic_identifiers(result: result, rule: rule)
              [ids, ReportTypeInference.infer_from(semantic_ids: ids)]
            end

            buckets[inferred] ||= build_typed_report(inferred, scanner)
            target = buckets[inferred]

            process_result(result, rules, scanner, orig_uris, target_report: target, semantic_ids: semantic_ids)
          end

          buckets.values
        end

        def build_typed_report(report_type, scanner)
          typed = ::Gitlab::Ci::Reports::Security::Report.new(report_type.to_s, report.pipeline, report.created_at)
          typed.scanner = scanner
          typed.add_scanner(scanner)
          typed.scanner_external_id = scanner.external_id
          typed
        end

        # Build a lookup hash: ruleId => rule object, scoped to the current run.
        # Rules are defined per-run inside tool.driver.rules (and optionally in
        # tool.extensions[].rules). Indexing per-run is correct: the SARIF spec
        # allows different runs to use the same ruleId with different definitions.
        # Rules are mutated in place: tags are capped, oversized text is truncated
        # and an oversized helpUri is removed.
        def index_rules(rules_array)
          return {} unless rules_array.is_a?(Array)

          rules = truncate(rules_array, MAX_RULES_PER_RUN, 'rules')
          enforce_tag_limits(rules)
          enforce_text_limits(rules)
          rules.index_by { |r| r['id'] }
        end

        def enforce_text_limits(rules)
          rules.each do |rule|
            truncate_text!(rule, 'name', :rule_name)
            truncate_text!(rule['shortDescription'], 'text', :short_description)
            truncate_text!(rule['fullDescription'], 'text', :full_description)
            drop_oversized_help_uri!(rule)
          end
        end

        def truncate_text!(container, key, field)
          return unless container.is_a?(Hash)

          value = container[key]
          return unless value.is_a?(String) && value.length > MAX_CHARS[field]

          container[key] = value.truncate(MAX_CHARS[field])
          @truncated_counts[field] += 1
        end

        # A truncated URL points somewhere else, so an oversized one is ignored.
        def drop_oversized_help_uri!(rule)
          uri = rule['helpUri']
          return unless uri.is_a?(String) && uri.length > MAX_CHARS[:help_uri]

          rule.delete('helpUri')
          @ignored_help_uris += 1
        end

        def enforce_tag_limits(rules)
          rules_with_excess_tags = rules.count do |rule|
            tags = rule.dig('properties', 'tags')
            next unless tags.is_a?(Array) && tags.size > MAX_TAGS_PER_RULE

            rule['properties']['tags'] = tags.first(MAX_TAGS_PER_RULE)
            true
          end

          return unless rules_with_excess_tags > 0

          add_ingestion_warning("#{rules_with_excess_tags} #{'rule'.pluralize(rules_with_excess_tags)} " \
            "had more than #{MAX_TAGS_PER_RULE} tags; excess tags were ignored.")
        end

        def rule_id_for(result)
          result['ruleId'] || result.dig('rule', 'id')
        end

        def build_scanner(driver)
          name = driver['name'].to_s
          ::Gitlab::Ci::Reports::Security::Scanner.new(
            external_id: name.downcase.gsub(/\s+/, '-').presence || 'sarif',
            name: name,
            vendor: driver['organization'] || driver['informationUri'],
            version: driver['version'] || driver['semanticVersion']
          )
        end

        def process_result(result, rules, scanner, orig_uris, target_report:, semantic_ids:)
          rule_id = rule_id_for(result)
          if rule_id.blank?
            @skip_reason_counts[:missing_rule_id] += 1
            Gitlab::AppLogger.info(message: "SARIF finding skipped: ruleId absent",
              result_message: message_text(result).to_s.truncate(100))
            return
          end

          rule = rules[rule_id] || {}
          severity = resolve_severity(result, rule)
          location = build_location(result, orig_uris)

          unless location
            @skip_reason_counts[:missing_location] += 1
            Gitlab::AppLogger.info(message: "SARIF finding skipped: no physicalLocation",
              rule_id: rule_id)
            return
          end

          text_fields = extract_text_fields(result, rule)
          truncate_message!(text_fields)

          identifiers = build_identifiers(rule_id, scanner,
            text_fields: text_fields, target_report: target_report, semantic_ids: semantic_ids)

          finding = ::Gitlab::Ci::Reports::Security::Finding.new(
            report_type: target_report.type.to_sym,
            name: finding_name(text_fields, identifiers),
            severity: ::Enums::Vulnerability.parse_severity_level(severity),
            confidence: nil,
            location: location,
            evidence: nil,
            scanner: scanner,
            scan: target_report.scan,
            identifiers: identifiers,
            flags: [],
            links: build_links(text_fields),
            remediations: [],
            original_data: result.merge(
              'description' => text_fields[:message] || text_fields[:full_description],
              'location' => location_data(location)
            ),
            metadata_version: report_data['version'],
            details: {},
            signatures: [],
            project_id: project.id,
            found_by_pipeline: target_report.pipeline,
            vulnerability_finding_signatures_enabled: false,
            cvss: [],
            tracked_context: target_report.tracked_context
          )

          if finding.uuid.present?
            target_report.add_finding(finding)
            @added_findings += 1
          else
            @skip_reason_counts[:nil_uuid_components] += 1
            Gitlab::AppLogger.info(message: "SARIF finding skipped: nil UUID components")
          end
        end

        # Severity resolution priority (highest to lowest):
        #   1. result.rank                         - 0.0-100.0 float; most precise when present.
        #                                            Negative values (e.g. -1, the SARIF "unset" default) are ignored.
        #   2. rule.properties.security-severity   - GitHub-convention CVSS-like float (0-10 scale);
        #                                            canonical location per SARIF convention
        #   3. result.properties.security-severity - some tools emit here instead
        #   4. result.level                        - SARIF enum: error|warning|note|none
        #   5. rule.defaultConfiguration.level     - rule author's default level
        #   6. DEFAULT_SEVERITY                    - safe fallback
        def resolve_severity(result, rule)
          rank = result['rank']

          if rank.is_a?(Numeric) && rank >= 0
            rank_to_severity(rank.to_f)
          else
            sec_sev = rule.dig('properties', 'security-severity').presence ||
              result.dig('properties', 'security-severity').presence

            if sec_sev
              rank_to_severity(sec_sev.to_f * 10)
            else
              level = result['level'] || rule.dig('defaultConfiguration', 'level')
              LEVEL_TO_SEVERITY.fetch(level, DEFAULT_SEVERITY)
            end
          end
        end

        # Ranges are exclusive at the top so that fractional ranks between the
        # bands, such as 9.95, do not fall through to `critical`.
        def rank_to_severity(rank)
          case rank
          when 0.0...10.0  then 'info'
          when 10.0...40.0 then 'low'
          when 40.0...70.0 then 'medium'
          when 70.0...90.0 then 'high'
          else                  'critical'
          end
        end

        # A result is suppressed when it has at least one suppression entry and none
        # of them are contested (underReview or rejected). This mirrors the logic in
        # the Go SARIF converter in the analyzers/report package.
        def suppressed?(result)
          suppressions = result['suppressions']
          return false if suppressions.blank?

          suppressions.none? { |s| s['status'] == 'underReview' || s['status'] == 'rejected' }
        end

        # Prefers the first physicalLocation. Falls back to nil (logical locations
        # like function names are not yet mapped).
        def build_location(result, orig_uris)
          ploc = result.dig('locations', 0, 'physicalLocation')
          return unless ploc

          uri    = resolve_uri(ploc['artifactLocation'], orig_uris)
          region = ploc['region'] || {}

          ::Gitlab::Ci::Reports::Security::Locations::Sarif.new(
            file_path: uri,
            start_line: region['startLine'],
            end_line: region['endLine'],
            start_column: region['startColumn'],
            end_column: region['endColumn']
          )
        end

        # Resolve uriBaseId references from originalUriBaseIds.
        # Most tools emit plain relative paths without uriBaseId; handle gracefully.
        def resolve_uri(artifact_location, orig_uris)
          return unless artifact_location.is_a?(Hash)

          uri     = artifact_location['uri'].to_s
          base_id = artifact_location['uriBaseId']

          if base_id && orig_uris[base_id]
            base_uri = orig_uris.dig(base_id, 'uri').to_s.delete_prefix('file://').delete_suffix('/')
            rel_uri = uri.delete_prefix('/')
            base_uri.empty? ? rel_uri : "#{base_uri}/#{rel_uri}"
          else
            uri.delete_prefix('file://').sub(%r{\A%[A-Z_]+%/?}, '')
          end
        end

        # Primary identifier: ruleId scoped to the tool name to prevent cross-tool
        # collisions when multiple SARIF reports are ingested for the same project.
        # Secondary identifiers: CWE/CVE tags from rule.properties.tags.
        def build_identifiers(rule_id, scanner, text_fields:, target_report:, semantic_ids:)
          ids       = []
          seen_keys = Set.new

          if rule_id.present?
            primary = ::Gitlab::Ci::Reports::Security::Identifier.new(
              external_type: scanner.external_id,
              external_id: rule_id,
              name: text_fields[:rule_name] || text_fields[:short_description] || rule_id,
              url: text_fields[:help_uri]
            )
            ids << target_report.add_identifier(primary) if seen_keys.add?(primary.key)
          end

          semantic_ids.each do |extracted|
            type = extracted[:type].to_s
            next unless SECONDARY_IDENTIFIER_TYPES.include?(type)

            external_id_value = extracted[:external_id]
            next if external_id_value.blank?

            secondary = ::Gitlab::Ci::Reports::Security::Identifier.new(
              external_type: type,
              external_id: external_id_value,
              name: extracted[:raw],
              url: identifier_url(type, external_id_value)
            )
            ids << target_report.add_identifier(secondary) if seen_keys.add?(secondary.key)
          end

          ids.compact
        end

        def identifier_url(type, value)
          case type
          when 'cwe' then "https://cwe.mitre.org/data/definitions/#{value.delete_prefix('CWE-')}.html"
          when 'cve' then "https://www.cve.org/CVERecord?id=CVE-#{value.upcase.delete_prefix('CVE-')}"
          end
        end

        def message_text(result)
          result.dig('message', 'text') || result.dig('message', 'markdown')
        end

        def full_description_text(rule)
          rule.dig('fullDescription', 'text')
        end

        def extract_text_fields(result, rule)
          {
            message: message_text(result),
            rule_name: rule['name'],
            short_description: rule.dig('shortDescription', 'text'),
            full_description: full_description_text(rule),
            help_uri: rule['helpUri']
          }
        end

        def truncate_message!(text_fields)
          message = text_fields[:message]
          return unless message.is_a?(String) && message.length > MAX_CHARS[:message]

          text_fields[:message] = message.truncate(MAX_CHARS[:message])
          @truncated_counts[:message] += 1
        end

        # An aborted scan stores nothing, so its truncation messages are only logged, not added as warnings.
        def add_truncation_warnings
          truncation_messages.each do |message|
            ingestion_aborted? ? log_ingestion(message) : add_ingestion_warning(message)
          end
        end

        # Rule fields are counted once per rule definition (per run) and the message once per result,
        # so each count states its unit.
        def truncation_messages
          messages = []

          if @truncated_counts.any?
            details = @truncated_counts.map do |field, count|
              unit = field == :message ? 'result' : 'rule'
              "`#{field}` (#{count} #{unit.pluralize(count)})"
            end.join(', ')
            messages << "Text fields that exceeded their character limit were truncated: #{details}."
          end

          if @ignored_help_uris > 0
            messages << "#{@ignored_help_uris} `help_uri` #{'value'.pluralize(@ignored_help_uris)} exceeded " \
              "the #{MAX_CHARS[:help_uri]}-character limit and #{@ignored_help_uris == 1 ? 'was' : 'were'} ignored."
          end

          messages
        end

        # Serialize the parsed location into the shape the rest of the GitLab
        # security pipeline expects in original_data['location']: the model reads
        # location['file'], location['start_line'], and location['end_line'].
        def location_data(location)
          return {} unless location

          {
            'file' => location.file_path,
            'start_line' => location.start_line,
            'end_line' => location.end_line
          }.compact
        end

        # Emit a warning or error depending on how many results were dropped.
        #
        # At or below the threshold (<=50%): record a warning so operators have visibility
        # into the partial drop without blocking ingestion of the valid subset.
        #
        # Above the threshold (>50%): record an error so StoreScanService sets
        # the scan status to :report_error. This surfaces clearly to the user that
        # the report is mostly unprocessable and likely reflects a configuration error
        # rather than an expected edge-case.
        #
        # The threshold is computed across the whole artifact, and the feedback is
        # stamped on every emitted typed report, as the signal reflects artifact-level health
        def add_ingestion_feedback(typed_reports)
          if ingestion_aborted?
            typed_reports.each { |r| r.add_error('Ingestion', ingestion_error_message) }
          else
            typed_reports.each { |r| r.add_warning('Ingestion', ingestion_warning_message) }
          end
        end

        def ingestion_drop_count
          @total_results - @added_findings
        end

        def ingestion_aborted?
          ingestion_drop_count > 0 && ingestion_drop_ratio > INGESTION_FAILURE_THRESHOLD
        end

        def ingestion_drop_ratio
          ingestion_drop_count.to_f / @total_results
        end

        def ingestion_warning_message
          "#{ingestion_drop_count} of #{@total_results} result(s) were skipped during ingestion. " \
            "Causes: #{skip_reason_breakdown}. " \
            "Check application logs for per-result details."
        end

        def ingestion_error_message
          "#{ingestion_drop_count} of #{@total_results} result(s) could not be ingested and the scan was aborted. " \
            "Causes: #{skip_reason_breakdown}. " \
            "Check application logs for per-result details."
        end

        def skip_reason_breakdown
          parts = SKIP_REASON_LABELS.filter_map do |reason, label|
            count = @skip_reason_counts[reason]
            next unless count > 0

            "#{label} (#{count})"
          end

          parts.empty? ? 'unknown' : parts.join(', ')
        end

        def build_links(text_fields)
          return [] unless text_fields[:help_uri].present?

          [::Gitlab::Ci::Reports::Security::Link.new(name: 'Rule documentation', url: text_fields[:help_uri])]
        end

        # Naming priority (highest to lowest):
        #   1. rule.shortDescription.text - stable, rule-authored title (preferred)
        #   2. result.message.text / .markdown - truncated to 255 chars
        #   3. rule.fullDescription.text - truncated to 255 chars
        #   4. identifiers.first.name - derived from ruleId
        #   5. 'Unknown finding' - absolute fallback
        def finding_name(text_fields, identifiers)
          return text_fields[:short_description] if text_fields[:short_description].present?
          return text_fields[:message].truncate(255) if text_fields[:message].present?
          return text_fields[:full_description].truncate(255) if text_fields[:full_description].present?

          identifiers.first&.name || 'Unknown finding'
        end

        def truncate(items, limit, label)
          return items if items.size <= limit

          warn_exceeds_maximum(items.size, limit, label, detail: "Only the first #{limit} were ingested.")
          items.first(limit)
        end

        def warn_exceeds_maximum(actual_value, limit, label, detail: nil)
          message = "SARIF run contains #{actual_value} #{label}, which exceeds the maximum of #{limit}."
          message += " #{detail}" if detail
          add_ingestion_warning(message)
        end

        def add_ingestion_warning(message)
          report.add_warning('Ingestion', message)
          log_ingestion(message)
        end

        # Warnings are recorded on the report we were given, but that report is dropped once a
        # run produced a typed report. Carry them over so they reach the persisted scan.
        def copy_warnings_to(typed_reports)
          report.warnings.each do |warning|
            typed_reports.each { |typed_report| typed_report.add_warning(warning[:type], warning[:message]) }
          end
        end

        def log_ingestion(message)
          Gitlab::AppLogger.warn(
            message: message,
            project_id: project.id,
            pipeline_id: report.pipeline&.id
          )
        end
      end
    end
  end
end
