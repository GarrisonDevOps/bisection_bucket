# frozen_string_literal: true

module Quality
  module Seeders
    class Vulnerabilities
      attr_reader :project

      def initialize(project)
        @project = project
      end

      def seed!
        if author.nil?
          print 'Skipping this project because it has no users'
          return
        end

        30.times do |rank|
          primary_identifier = create_identifier(rank)
          finding = create_finding(rank, primary_identifier)

          # This transaction is only necessary to attach the feature flag for the database trigger
          SecApplicationRecord.feature_flagged_transaction_for(project) do
            vulnerability = create_vulnerability(finding: finding, rank: rank)

            # The primary identifier is already associated via the finding creation
            # Only add additional identifier if rank % 3 == 0 and it's different from primary
            if rank % 3 == 0
              secondary_identifier = create_identifier(rank + 1000) # Ensure it's different
              finding.identifiers << secondary_identifier unless finding.identifiers.include?(secondary_identifier)
            end

            finding.update!(vulnerability_id: vulnerability.id)

            create_vulnerability_read(vulnerability, finding)

            case rank % 3
            when 0
              create_feedback(finding, 'dismissal')
            when 1
              create_feedback(finding, 'issue', vulnerability: vulnerability)
            end

            print '.'
          end
        end
      end

      private

      def create_vulnerability(finding:, rank:)
        states = ::Vulnerability.states.keys
        state_symbol = states[rank % states.size].to_sym
        vulnerability = build_vulnerability(state_symbol, rank)
        vulnerability.finding_id = finding.id

        case state_symbol
        when :resolved
          vulnerability.resolved_by = author
        when :dismissed
          vulnerability.dismissed_by = author
        end

        vulnerability.tap(&:save!)
      end

      def build_vulnerability(state_symbol, rank)
        FactoryBot.build(
          :vulnerability,
          state_symbol,
          project: project,
          author: author,
          title: 'Cypher with no integrity',
          severity: severity_level_for(rank),
          report_type: report_type_for(rank)
        )
      end

      def create_finding(rank, primary_identifier)
        scanner = find_or_create_scanner

        # Generate a unique location fingerprint for each finding
        unique_fingerprint = Digest::SHA1.hexdigest("#{random_fingerprint}_#{rank}_#{Time.current.to_i}") # rubocop:disable Fips/SHA1 -- This is the hash function we use in applicaiton layer logic

        FactoryBot.create(
          :vulnerabilities_finding,
          :with_pipeline,
          project: project,
          scanner: scanner,
          severity: severity_level_for(rank),
          primary_identifier: primary_identifier,
          location_fingerprint: unique_fingerprint,
          raw_metadata: Gitlab::Json.dump(metadata(rank))
        )
      end

      def find_or_create_scanner
        # Reuse scanner if it exists to avoid uniqueness violations
        # rubocop:disable CodeReuse/ActiveRecord
        @scanner ||= ::Vulnerabilities::Scanner.find_or_create_by!(
          project: project,
          external_id: 'security-scanner'
        ) do |scanner|
          scanner.name = 'Security Scanner'
        end
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def create_identifier(rank)
        # Try to find existing identifier first
        external_id = "SECURITY_#{rank}"
        # rubocop:disable CodeReuse/ActiveRecord
        existing_identifier = ::Vulnerabilities::Identifier.find_by(
          project: project,
          external_type: "SECURITY_ID",
          external_id: external_id
        )
        # rubocop:enable CodeReuse/ActiveRecord

        return existing_identifier if existing_identifier

        # If not found, create with unique ID to avoid conflicts
        timestamp = Time.current.to_i
        unique_id = "#{rank}_#{timestamp}_#{SecureRandom.hex(4)}"

        FactoryBot.create(
          :vulnerabilities_identifier,
          external_type: "SECURITY_ID",
          external_id: "SECURITY_#{unique_id}",
          fingerprint: random_fingerprint,
          name: "SECURITY_IDENTIFIER #{rank}",
          url: "https://security.example.com/#{unique_id}",
          project: project
        )
      end

      def create_feedback(finding, type, vulnerability: nil)
        issue = create_issue("Dismiss #{finding.name}") if type == 'issue'
        if vulnerability && issue
          create_vulnerability_issue_link(vulnerability, issue)
          vulnerability.vulnerability_read.update(has_issues: true)
        end

        FactoryBot.create(
          :vulnerability_feedback,
          feedback_type: type,
          project: project,
          author: author,
          issue: issue,
          pipeline: pipeline
        )
      end

      def create_issue(title)
        FactoryBot.create(
          :issue,
          project: project,
          author: author,
          title: title
        )
      end

      def create_vulnerability_issue_link(vulnerability, issue)
        FactoryBot.create(
          :vulnerabilities_issue_link,
          :created,
          vulnerability: vulnerability,
          issue: issue
        )
      end

      def create_vulnerability_read(vulnerability, finding)
        # Skip if vulnerability_read already exists
        # rubocop:disable CodeReuse/ActiveRecord
        return if ::Vulnerabilities::Read.exists?(vulnerability_id: vulnerability.id)

        # rubocop:enable CodeReuse/ActiveRecord

        ::Vulnerabilities::Read.create!(
          vulnerability_id: vulnerability.id,
          project_id: vulnerability.project_id,
          scanner_id: finding.scanner_id,
          report_type: vulnerability.report_type,
          severity: vulnerability.severity,
          state: vulnerability.state,
          resolved_on_default_branch: vulnerability.resolved_on_default_branch,
          uuid: finding.uuid,
          location_image: vulnerability.location&.dig('image'),
          cluster_agent_id: vulnerability.location&.dig('kubernetes_resource', 'agent_id'),
          casted_cluster_agent_id: vulnerability.location&.dig('kubernetes_resource', 'agent_id')&.to_i,
          has_issues: vulnerability.issue_links.any?,
          has_merge_request: vulnerability.merge_request_links.any?,
          traversal_ids: vulnerability.project.namespace.traversal_ids,
          archived: vulnerability.project.archived,
          identifier_names: finding.identifiers.map(&:name),
          owasp_top_10: -1,
          has_vulnerability_resolution: false
        )
      rescue ActiveRecord::RecordInvalid => e
        print "\nFailed to create vulnerability_read for vulnerability #{vulnerability.id}: #{e.message}\n"
      end

      # Advances once per full state cycle rather than per rank: state and severity counts share a
      # factor, so stepping both by rank leaves half the state/severity pairs unseeded.
      def severity_level_for(rank)
        levels = ::Enums::Vulnerability.severity_levels.keys
        levels[(rank / ::Vulnerability.states.size) % levels.size]
      end

      # Sorted by value here rather than trusting the enum's key order, so rank 0 is always the
      # lowest report type - the only one the coverage check reads as zero.
      def report_type_for(rank)
        types = ::Enums::Vulnerability.report_types.sort_by(&:last).map(&:first)
        types[rank % types.size]
      end

      def metadata(line)
        {
          description: "The cipher does not provide data integrity update 1",
          solution: "GCM mode introduces an HMAC into the resulting encrypted data, providing integrity of the result.",
          location: {
            file: "maven/src/main/java//App.java",
            start_line: line,
            end_line: line,
            class: "com.gitlab..App",
            method: "insecureCypher"
          },
          links: [
            {
              name: "Cipher does not check for integrity first?",
              url: "https://crypto.stackexchange.com/questions/31428/pbewithmd5anddes-cipher-does-not-check-for-integrity-first"
            }
          ]
        }
      end

      def random_fingerprint
        SecureRandom.hex(20)
      end

      def pipeline
        @pipeline ||= ::Ci::ProjectPipelines.new(project).latest_in_default_branch
      end

      def author
        @author ||= project.users.first
      end
    end
  end
end
