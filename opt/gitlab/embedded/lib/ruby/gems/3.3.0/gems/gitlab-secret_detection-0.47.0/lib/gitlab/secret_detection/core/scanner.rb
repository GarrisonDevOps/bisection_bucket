# frozen_string_literal: true

require 're2'
require 'logger'
require 'timeout'
require 'English'
require 'parallel'
require_relative '../utils/memoize'

module Gitlab
  module SecretDetection
    module Core
      # Scan is responsible for running Secret Detection scan operation
      class Scanner
        include ::Gitlab::SecretDetection::Utils::StrongMemoize

        # default time limit(in seconds) for running the scan operation per invocation
        DEFAULT_SCAN_TIMEOUT_SECS = 180 # 3 minutes
        # default time limit(in seconds) for running the scan operation on a single payload
        DEFAULT_PAYLOAD_TIMEOUT_SECS = 30 # 30 seconds
        # Max no of child processes to spawn per request
        # ref: https://gitlab.com/gitlab-org/gitlab/-/issues/430160
        MAX_PROCS_PER_REQUEST = 5
        # Minimum cumulative size of the payloads required to spawn and
        # run the scan within a new subprocess.
        MIN_CHUNK_SIZE_PER_PROC_BYTES = 2_097_152 # 2MiB
        # Whether to run scan in subprocesses or not. Default is false.
        RUN_IN_SUBPROCESS = ENV.fetch('GITLAB_SD_RUN_IN_SUBPROCESS', false)
        # Default limit for max findings to be returned in the scan
        DEFAULT_MAX_FINDINGS_LIMIT = 999
        # Rules whose capture group is incorrectly capturing part of the secret
        # instead of entire secret. We capture the whole match instead of captured
        # match when extracting the secret
        WHOLE_MATCH_RULE_IDS = Set[
          'Adobe Client Secret',
          'ContentfulPersonalAccessToken',
          'Github App Token',
          'Slack token'
        ].freeze

        # Initializes the instance with logger along with following operations:
        # 1. Filter the parsed ruleset down to rules applicable to push protection based on
        # their structured `scanningCapabilities` field.
        # 2. Extract keywords from the applicable rules to use for matching keywords before regex operation.
        # 3. Build and Compile rule regex patterns obtained from the applicable rules.
        # Raises +RulesetCompilationError+ in case the regex pattern compilation fails.
        def initialize(rules:, logger: Logger.new($stdout))
          @logger = logger
          selected_rules = select_push_protection_rules(rules)
          keywordless_rules, keyword_rules = selected_rules.partition { |rule| Array(rule[:keywords]).empty? }
          # Rules with no keywords come first, so that the indexes of their pattern matcher are also indexes in @rules.
          @rules = (keywordless_rules + keyword_rules).freeze
          @keywords = create_keywords(@rules)
          @keyword_matcher = build_keyword_matcher(@keywords)
          @pattern_matcher = build_pattern_matcher(@rules)
          @keywordless_pattern_matcher = build_pattern_matcher(keywordless_rules) unless keywordless_rules.empty?
        end

        # Runs Secret Detection scan on the list of given payloads. Both the total scan duration and
        # the duration for each payload is time bound via +timeout+ and +payload_timeout+ respectively.
        #
        # +payloads+:: Array of payloads where each payload should have `id` and `data` properties.
        # +timeout+:: No of seconds(accepts floating point for smaller time values) to limit the total scan duration
        # +payload_timeout+:: No of seconds(accepts floating point for smaller time values) to limit
        #                  the scan duration on each payload
        # +exclusions+:: Hash with keys: :raw_value, :rule and values of arrays of either
        #           GRPC::Exclusion objects (when used as a standalone service)
        #           or Security::ProjectSecurityExclusion objects (when used as gem).
        #           :raw_value - Exclusions in the :raw array are the raw values to ignore.
        #           :rule - Exclusions in the :rule array are the rules to exclude from the ruleset used for the scan.
        #           Each rule is represented by its ID. For example: `gitlab_personal_access_token`
        #           for representing Gitlab Personal Access Token. By default, no rule is excluded from the ruleset.
        # +tags+:: Deprecated and ignored. Rules are selected via their structured
        #           `scanningCapabilities` field instead of tags. The argument is kept only
        #           for backward compatibility with existing callers and will be removed.
        # +max_findings_limit+:: Integer to limit the number of findings to be returned in the scan. Defaults
        #           to 999 (+DEFAULT_MAX_FINDINGS_LIMIT+).
        # +include_raw_value+:: Whether each finding should carry the substring it matched, on
        #           +Finding#raw_value+. Defaults to false. Callers that opt in receive secrets in
        #           memory and are responsible for keeping them out of logs and other sinks. In
        #           subprocess mode the value travels back from the child through a +Parallel+ IPC pipe.
        #
        #           LIMITATION: one finding per rule per line, so two secrets of the *same* rule on one
        #           line yield one +raw_value+, the leftmost. Not an exhaustive list of a line's secrets.
        #
        # NOTE:
        # Running the scan in fork mode primarily focuses on reducing the memory consumption of the scan by
        # offloading regex operations on large payloads to sub-processes. However, it does not assure the improvement
        # in the overall latency of the scan, specifically in the case of smaller payloads, where the overhead of
        # forking a new process adds to the overall latency of the scan instead. More reference on Subprocess-based
        # execution is found here: https://gitlab.com/gitlab-org/gitlab/-/issues/430160.
        #
        # Returns an instance of Gitlab::SecretDetection::Core::Response by following below structure:
        # {
        #     status: One of the Core::Status values
        #     results: [SecretDetection::Finding]
        # }
        #
        def secrets_scan(
          payloads,
          timeout: DEFAULT_SCAN_TIMEOUT_SECS,
          payload_timeout: DEFAULT_PAYLOAD_TIMEOUT_SECS,
          exclusions: {},
          tags: [],
          subprocess: RUN_IN_SUBPROCESS,
          max_findings_limit: DEFAULT_MAX_FINDINGS_LIMIT,
          include_raw_value: false
        )
          return Core::Response.new(status: Core::Status::INPUT_ERROR) unless validate_scan_input(payloads)

          # assign defaults since grpc passing zero timeout value to `Timeout.timeout(..)` makes it effectively useless.
          timeout = DEFAULT_SCAN_TIMEOUT_SECS unless timeout.positive?
          payload_timeout = DEFAULT_PAYLOAD_TIMEOUT_SECS unless payload_timeout.positive?

          unless tags.nil? || tags.empty? || @tags_deprecation_warned
            @tags_deprecation_warned = true
            logger.warn(
              message: "The `tags` argument is deprecated and ignored. Rules are selected via their " \
                "`scanningCapabilities` field instead.",
              given_tags: tags
            )
          end

          # Before the timeout, so the one-off compile is not charged to the scan budget, a bad
          # pattern fails loudly, and forked children inherit the patterns instead of recompiling.
          compiled_regexes if include_raw_value

          Timeout.timeout(timeout) do
            matched_payloads = filter_by_keywords(keyword_matcher, payloads)
            # Rules with no keywords also apply to the payloads that the keyword prefilter drops.
            unmatched_payloads = keywordless_pattern_matcher ? payloads - matched_payloads : []

            if matched_payloads.empty? && unmatched_payloads.empty?
              next Core::Response.new(status: Core::Status::NOT_FOUND)
            end

            scan_args = {
              payload_timeout:,
              rules:,
              exclusions:,
              include_raw_value:
            }.freeze

            logger.info(
              message: "Scan input parameters for running Secret Detection scan",
              timeout:,
              payload_timeout:,
              given_total_payloads: payloads.length,
              keyword_matched_payloads: matched_payloads.length,
              payloads_for_keywordless_rules: unmatched_payloads.length,
              active_rules: rules.length,
              run_in_subprocess: subprocess,
              max_findings_limit:,
              given_exclusions: format_exclusions_hash(exclusions)
            )

            secrets, applied_exclusions = scan_payload_groups(
              matched_payloads, unmatched_payloads, subprocess:, max_findings_limit:, **scan_args
            )

            scan_status = overall_scan_status(secrets)

            logger.info(
              message: "Secret Detection scan completed with #{secrets.length} secrets detected in the given payloads",
              detected_secrets_metadata: format_detected_secrets_metadata(secrets),
              applied_exclusions: format_exclusions_arr(applied_exclusions)
            )

            Core::Response.new(status: scan_status, results: secrets, applied_exclusions:)
          end
        rescue Timeout::Error => e
          logger.error "Secret detection operation timed out: #{e}"

          Core::Response.new(status: Core::Status::SCAN_TIMEOUT)
        end

        private

        attr_reader :logger, :rules, :keywords, :pattern_matcher, :keyword_matcher, :keywordless_pattern_matcher

        # A rule applies to push protection when its structured `scanningCapabilities`
        # field includes `pushProtection`. Rules without the field are included for
        # backward compatibility: ruleset artifacts released before the structured
        # fields refactor (https://gitlab.com/gitlab-org/gitlab/-/work_items/592827)
        # do not carry it and are already limited to push protection rules when the
        # artifact is generated.
        def push_protection_rule?(rule)
          capabilities = rule[:scanningCapabilities]

          capabilities.nil? || capabilities[:pushProtection] == true
        end

        # Filters the given ruleset down to push protection rules and logs how
        # it was narrowed, so that a malformed ruleset artifact is visible in
        # the logs at startup.
        def select_push_protection_rules(rules)
          selected = rules.select { |rule| push_protection_rule?(rule) }.freeze
          log_selected_rules(selected, total_rules_given: rules.length)
          selected
        end

        # An empty selection is logged as an error because every scan would
        # then return no findings.
        def log_selected_rules(selected_rules, total_rules_given:)
          if selected_rules.empty?
            logger.error(
              message: "No rules with the pushProtection scanning capability found in the given ruleset. " \
                "All scans will return no findings.",
              total_rules_given:
            )
            return
          end

          logger.info(
            message: "Selected push protection rules from the given ruleset",
            total_rules_given:,
            push_protection_rules_selected: selected_rules.length,
            selected_without_scanning_capabilities: selected_rules.count { |rule| rule[:scanningCapabilities].nil? }
          )
        end

        # Builds RE2::Set pattern matcher for the given rules. The matcher's
        # pattern indices align with the order of the given rules.
        def build_pattern_matcher(rules)
          matcher = RE2::Set.new

          begin
            rules.each do |rule|
              matcher.add(rule[:regex])
            end
          rescue StandardError => e
            logger.error "Failed to add regex secret detection ruleset in RE::Set: #{e.message}"
            raise Core::Ruleset::RulesetCompilationError, cause: e
          end

          unless matcher.compile
            logger.error "Failed to compile secret detection ruleset in RE::Set"

            raise Core::Ruleset::RulesetCompilationError
          end

          matcher
        end

        # Creates and returns the unique set of rule matching keywords
        def create_keywords(rules)
          secrets_keywords = Set.new

          rules.each do |rule|
            secrets_keywords.merge rule[:keywords] unless rule[:keywords].nil?
          end

          secrets_keywords.freeze
        end

        # Builds RE2 keyword matcher from the given set of keywords. Returns
        # nil when the set is empty, in which case the keyword-based
        # payload prefilter is skipped.
        def build_keyword_matcher(keywords)
          logger.info(
            message: "Creating RE2 Keyword Matcher",
            keywords_count: keywords.size
          )

          if keywords.empty?
            logger.error(
              message: "No rule keywords found in the given rules, returning empty RE2 Keyword Matcher"
            )
            return nil
          end

          keywords_regex = keywords.map { |keyword| RE2::Regexp.quote(keyword) }.join('|')

          logger.debug(
            message: "Creating RE2 Keyword Matcher with set of rule keywords",
            keywords: keywords.to_a
          )

          # Without log_errors: false, RE2 writes the pattern to STDERR.
          keyword_matcher = RE2::Regexp.new("(#{keywords_regex})", log_errors: false)
          return keyword_matcher if keyword_matcher.ok?

          # A matcher that does not compile matches no payload.
          logger.error(
            message: "Failed to compile the RE2 Keyword Matcher. The scan skips the keyword prefilter and directly " \
              "scans all payloads with rule regex patterns.",
            keywords_count: keywords.size,
            error: keyword_matcher.error
          )
          nil
        end

        def filter_by_keywords(keyword_matcher, payloads)
          if keyword_matcher.nil?
            logger.warn "No RE2 Keyword Matcher instance available, skipping payload filter by rule keywords step.."
            return payloads
          end

          matched_payloads = []
          payloads.each do |payload|
            next unless keyword_matcher.partial_match?(payload.data)

            matched_payloads << payload
          end

          total_payloads_retained = matched_payloads.length == payloads.length ? 'all' : matched_payloads.length
          log_message = if matched_payloads.empty?
                          "No payloads available to scan further after keyword-matching, exiting Secret Detection scan"
                        else
                          "Retained #{total_payloads_retained} payloads to scan further after keyword-matching step"
                        end

          logger.info(
            message: log_message,
            given_total_payloads: payloads.length,
            matched_payloads: matched_payloads.length,
            payloads_to_scan_further: matched_payloads.map(&:id)
          )

          matched_payloads
        end

        # Scans the payloads that have a keyword with all rules, and the other payloads
        # with only the rules that have no keywords.
        def scan_payload_groups(matched_payloads, unmatched_payloads, subprocess:, max_findings_limit:, **scan_args)
          secrets = []
          applied_exclusions = []
          groups = [[matched_payloads, pattern_matcher], [unmatched_payloads, keywordless_pattern_matcher]]

          groups.each do |group, matcher|
            remaining_limit = max_findings_limit - secrets.length
            next if group.empty? || remaining_limit <= 0

            args = scan_args.merge(payloads: group, pattern_matcher: matcher, max_findings_limit: remaining_limit)
            found, excluded = subprocess ? run_scan_within_subprocess(**args) : run_scan(**args)
            secrets.concat(found)
            applied_exclusions |= excluded
          end

          [secrets, applied_exclusions]
        end

        # Runs the secret detection scan on the given list of payloads. It accepts
        # literal values to exclude from the input before the scan, also SD rules to exclude during
        # the scan when performed on the payloads.
        def run_scan(
          payloads:,
          payload_timeout:,
          pattern_matcher:,
          max_findings_limit:,
          rules:,
          include_raw_value:,
          exclusions: {})
          all_applied_exclusions = Set.new

          logger.info(
            message: "Running Secret Detection scan sequentially",
            payload_timeout:
          )

          capped_findings = payloads.lazy.flat_map do |payload|
            Timeout.timeout(payload_timeout) do
              findings, applied_exclusions = find_secrets_in_payload(
                payload:,
                pattern_matcher:,
                exclusions:,
                rules:,
                include_raw_value:
              )
              all_applied_exclusions.merge(applied_exclusions)
              findings
            end
          rescue Timeout::Error => e
            logger.warn "Secret Detection scan timed out on the payload(id:#{payload.id}): #{e}"

            Core::Finding.new(payload.id,
              Core::Status::PAYLOAD_TIMEOUT)
          end.take(max_findings_limit).to_a

          [capped_findings, all_applied_exclusions.to_a]
        end

        def run_scan_within_subprocess(
          payloads:,
          payload_timeout:,
          pattern_matcher:,
          max_findings_limit:,
          rules:,
          include_raw_value:,
          exclusions: {}
        )
          all_applied_exclusions = Set.new

          payload_sizes = payloads.map(&:size)
          grouped_payload_indices = group_by_chunk_size(payload_sizes)

          grouped_payloads = grouped_payload_indices.map { |idx_arr| idx_arr.map { |i| payloads[i] } }

          logger.info(
            message: "Running Secret Detection scan within a subprocess",
            grouped_payloads: grouped_payloads.length,
            payload_timeout:
          )

          found_secrets = []

          grouped_payloads.each do |grouped_payload|
            break if found_secrets.length >= max_findings_limit

            batch_results = Parallel.map(
              grouped_payload,
              in_processes: MAX_PROCS_PER_REQUEST,
              isolation: true # do not reuse sub-processes
            ) do |payload|
              Timeout.timeout(payload_timeout) do
                findings, applied_exclusions = find_secrets_in_payload(
                  payload:,
                  pattern_matcher:,
                  exclusions:,
                  rules:,
                  include_raw_value:
                )
                [findings, applied_exclusions]
              end
            rescue Timeout::Error => e
              logger.warn "Secret Detection scan timed out on the payload(id:#{payload.id}): #{e}"

              # Must match the happy path's shape: the consumer destructures each element into
              # `findings, applied_exclusions`. A bare Finding made `Set#merge(nil)` raise.
              [[Core::Finding.new(payload.id, Core::Status::PAYLOAD_TIMEOUT)], []]
            end

            # Process results and collect exclusions
            batch_results.each do |findings, applied_exclusions|
              all_applied_exclusions.merge(applied_exclusions)

              remaining_slots = max_findings_limit - found_secrets.length
              found_secrets.concat(findings.take(remaining_slots))

              break if found_secrets.length >= max_findings_limit
            end
          end

          [found_secrets, all_applied_exclusions.to_a]
        end

        # Finds secrets in the given payload guarded with a timeout as a circuit breaker. It accepts
        # literal values to exclude from the input before the scan, also SD rules to exclude during
        # the scan.
        def find_secrets_in_payload(payload:, pattern_matcher:, rules:, exclusions: {}, include_raw_value: false)
          findings = []
          applied_exclusions = Set.new

          payload_offset = payload.respond_to?(:offset) ? payload.offset : 0

          raw_value_exclusions = exclusions.fetch(:raw_value, [])
          rule_exclusions = exclusions.fetch(:rule, [])

          payload.data
                 .each_line($INPUT_RECORD_SEPARATOR, chomp: true)
                 .each_with_index do |line, index|
            unless raw_value_exclusions.empty?
              raw_value_exclusions.each do |exclusion|
                # replace input that doesn't contain allowed value in it
                # replace exclusion value, `.gsub!` returns 'self' if replaced otherwise 'nil'
                excl_replaced = !!line.gsub!(exclusion.value, '')
                applied_exclusions << exclusion if excl_replaced
              end
            end

            next if line.empty?

            # If payload offset is given then we will compute absolute line number i.e.,
            # offset + relative_line_number - 1. In this scenario, index is equivalent to relative_line_number - 1.
            # Whereas, when payload offset is not given, we'll set the line number relative to the beginning of the
            # payload. In this scenario it will be index + 1.
            line_no = payload_offset.positive? ? payload_offset + index : index + 1

            matches = pattern_matcher.match(line, exception: false) # returns indices of matched patterns

            matches.each do |match_idx|
              rule = rules[match_idx]

              next if applied_rule_exclusion?(rule[:id], rule_exclusions, applied_exclusions)

              findings << build_finding(
                payload_id: payload.id, line_no:, rule:, rule_index: match_idx, line:, include_raw_value:
              )
            end
          end

          logger.info(
            message: "Secret Detection scan found #{findings.length} secret leaks in the payload(id:#{payload.id})",
            payload_id: payload.id,
            detected_rules: findings.map { |f| "#{f.type}:#{f.line_number}" },
            applied_exclusions: format_exclusions_arr(applied_exclusions)
          )

          [findings, applied_exclusions]
        rescue StandardError => e
          logger.error "Secret Detection scan failed on the payload(id:#{payload.id}): #{e}"

          [[Core::Finding.new(payload.id, Core::Status::SCAN_ERROR)], []]
        end

        def build_finding(payload_id:, line_no:, rule:, rule_index:, line:, include_raw_value:)
          secret = include_raw_value ? extract_raw_value(rule, rule_index, line) : nil
          Core::Finding.new(
            payload_id,
            Core::Status::FOUND,
            line_no,
            rule[:id],
            Core::Ruleset.finding_description(rule),
            raw_value: secret
          )
        end

        # Returns the substring of +line+ that the rule actually matched, or nil when it does not
        # match. +line+ has already had raw value exclusions stripped out of it by the caller, so
        # this can never return an allowlisted secret.
        #
        # RE2::Set reports which patterns hit but not where, so the pattern is run again to locate
        # the match; with two secrets of the same rule on a line this returns the leftmost.
        # +rule_index+ indexes +compiled_regexes+, which is built from the scanner's own +rules+,
        # so callers must pass that same array as +rules:+ or extraction returns nil.
        def extract_raw_value(rule, rule_index, line)
          regex = compiled_regexes[rule_index]

          # RE2 returns `true` rather than a match object when a pattern has no capturing groups and
          # `submatches` is left at its default, so this argument is necessary. One more than the
          # group count leaves `match[1]` nil for a group-less pattern.
          match = regex.match(line, submatches: regex.number_of_capturing_groups + 1)
          return unless match

          return match[0] if WHOLE_MATCH_RULE_IDS.include?(rule[:id])

          match[1] || match[0]
        rescue StandardError => e
          logger.warn(message: "Failed to extract the matched value", rule_id: rule[:id], error: e.class.name)
          nil
        end

        # +RE2::Set+ does not expose its compiled patterns, so extraction needs its own +RE2::Regexp+
        # per rule, in an Array aligned with the indices RE2::Set reports. Built once and frozen so it
        # is fork-inheritable and not a shared mutable; lazy so opt-out scans pay nothing.
        def compiled_regexes
          strong_memoize(:compiled_regexes) do
            build_compiled_regexes(rules)
          end
        end

        # +RE2::Regexp.new+ does not raise on a bad pattern; it returns one whose +ok?+ is false and
        # +number_of_capturing_groups+ is -1, which makes +submatches+ zero and flips +match+ to a
        # boolean, silently nilling every raw_value for that rule. Fail loudly instead.
        def build_compiled_regexes(rules)
          compiled = rules.map { |rule| RE2::Regexp.new(rule[:regex]) }

          invalid = rules.zip(compiled).reject { |_rule, regex| regex.ok? }
          unless invalid.empty?
            logger.error(
              message: "Failed to compile individual secret detection rule patterns for raw value extraction",
              rule_ids: invalid.map { |rule, _regex| rule[:id] },
              errors: invalid.map { |_rule, regex| regex.error }
            )

            raise Core::Ruleset::RulesetCompilationError
          end

          compiled.freeze
        end

        def applied_rule_exclusion?(type, rule_exclusions, applied_exclusions)
          applied_exclusion = rule_exclusions&.find { |rule_exclusion| rule_exclusion.value == type }
          applied_exclusion && (applied_exclusions << applied_exclusion)
        end

        # Validates the given payloads by verifying the type and
        # presence of `id` and `data` fields necessary for the scan
        def validate_scan_input(payloads)
          if payloads.nil? || !payloads.instance_of?(Array)
            logger.debug(message: "Scan input validation error: payloads arg is empty or not instance of array")
            return false
          end

          payloads.all? do |payload|
            has_valid_fields = payload.respond_to?(:id) && payload.respond_to?(:data) && payload.data.is_a?(String)
            unless has_valid_fields
              logger.debug(
                message: "Scan input validation error: one of the payloads does not respond to `id` or `data`"
              )
            end

            has_valid_fields
          end
        end

        # Returns the status of the overall scan request
        # based on the detected secret findings found in the input payloads
        def overall_scan_status(found_secrets)
          return Core::Status::NOT_FOUND if found_secrets.empty?

          timed_out_payloads = found_secrets.count { |el| el.status == Core::Status::PAYLOAD_TIMEOUT }

          case timed_out_payloads
          when 0
            Core::Status::FOUND
          when found_secrets.length
            Core::Status::SCAN_TIMEOUT
          else
            Core::Status::FOUND_WITH_ERRORS
          end
        end

        # This method accepts an array of payload sizes(in bytes) and groups them into an array
        # of arrays structure where each element is the group of indices of the input
        # array whose cumulative payload sizes has at least +MIN_CHUNK_SIZE_PER_PROC_BYTES+
        def group_by_chunk_size(payload_size_arr)
          cumulative_size = 0
          chunk_indexes = []
          chunk_idx_start = 0

          payload_size_arr.each_with_index do |size, index|
            cumulative_size += size
            next unless cumulative_size >= MIN_CHUNK_SIZE_PER_PROC_BYTES

            chunk_indexes << (chunk_idx_start..index).to_a

            chunk_idx_start = index + 1
            cumulative_size = 0
          end

          if cumulative_size.positive? && (chunk_idx_start < payload_size_arr.length)
            chunk_indexes << if chunk_idx_start == payload_size_arr.length - 1
                               [chunk_idx_start]
                             else
                               (chunk_idx_start..payload_size_arr.length - 1).to_a
                             end
          end

          chunk_indexes
        end

        # Returns array of strings with each representing a masked exclusion
        #
        # Example: For given arg exclusions = {
        #     rule: ["gitlab_personal_access_token", "aws_key"],
        #     path: ["test.py"],
        #     raw_value: ["ABC123XYZ"]
        # }
        #
        # The output will look like the following:
        # [
        #   "rule=gitlab_personal_access_token,aws_key",
        #   "raw_value=AB*****YZ",
        #   "paths=test.py"
        # ]
        def format_exclusions_hash(exclusions = {})
          masked_raw_values = exclusions.fetch(:raw_value, []).map do |exclusion|
            Gitlab::SecretDetection::Utils::Masker.mask_secret(exclusion.value)
          end.join(", ")
          paths = exclusions.fetch(:path, []).map(&:value).join(", ")
          rules = exclusions.fetch(:rule, []).map(&:value).join(", ")

          out = []

          out << "rules=#{rules}" unless rules.empty?
          out << "raw_values=#{masked_raw_values}" unless masked_raw_values.empty?
          out << "paths=#{paths}" unless paths.empty?

          out
        end

        def format_exclusions_arr(exclusions = [])
          return [] if exclusions.empty?

          masked_raw_values = Set.new
          paths = Set.new
          rules = Set.new

          exclusions.each do |exclusion|
            case exclusion.exclusion_type
            when :EXCLUSION_TYPE_RAW_VALUE
              masked_raw_values << Gitlab::SecretDetection::Utils::Masker.mask_secret(exclusion.value)
            when :EXCLUSION_TYPE_RULE
              rules << exclusion.value
            when :EXCLUSION_TYPE_PATH
              paths << exclusion.value
            else
              logger.warn("Unknown exclusion type #{exclusion.exclusion_type}")
            end
          end

          out = []

          out << "rules=#{rules.join(',')}" unless rules.empty?
          out << "raw_values=#{masked_raw_values.join(',')}" unless masked_raw_values.empty?
          out << "paths=#{paths.join(',')}" unless paths.empty?

          out
        end

        def format_detected_secrets_metadata(findings = [])
          return [] if findings.empty?

          found_secrets = findings.filter do |f|
            f.status == Core::Status::FOUND
          end

          found_secrets.map { |f| "#{f.payload_id}=>#{f.type}:#{f.line_number}" }
        end
      end
    end
  end
end
