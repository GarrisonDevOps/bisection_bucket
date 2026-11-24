# frozen_string_literal: true

module Security
  module SecretDetection
    class ValidityCheckDocs
      DOC_PATH = Rails.root.join('doc/user/application_security/secret_detection/detected_secrets.md')
      HEADING = '## Supported rules for rule-based detection'
      YES = '{{< yes >}}'
      NO = '{{< no >}}'
      BOTH = 'Both'
      GSS = 'GitLab Secret Scanning for Source Code'
      NONE = 'None'

      # Cell indexes after line.split('|', -1): [0] is the empty text before the first pipe.
      ID_CELL = 2
      VALIDITY_CELL = 6
      ANALYZER_CELL = 7

      class << self
        # @return [Array(String, Array<String>)] new file content, and rule IDs that have no row in the table
        def generate(content = File.read(DOC_PATH))
          rules = validity_by_rule_id
          in_table = false
          table_ids = []

          lines = content.lines.map do |line|
            in_table = line.start_with?(HEADING) if line.start_with?('## ')
            next line unless in_table && line.start_with?('|')

            cells = line.chomp.split('|', -1)
            id = cells[ID_CELL].to_s.strip
            next line if id.match?(/\A:?-+:?\z/) # separator row

            if id == 'ID' # header row
              validate_header!(cells)
              next line
            end

            table_ids << id
            analyzer = rules.fetch(id, NONE)
            cells[VALIDITY_CELL] = " #{analyzer == NONE ? NO : YES} "
            cells[ANALYZER_CELL] = " #{analyzer} "
            "#{cells.join('|')}\n"
          end

          [lines.join, rules.keys - table_ids]
        end

        private

        # Union of both sources, so a rule that appears in each keeps every scanner.
        def validity_by_rule_id
          targets = Hash.new { |hash, key| hash[key] = [] }

          TokenLookupService::TOKEN_TYPE_CONFIG.each_key do |id|
            targets[id] |= TokenLookupService.enabled_targets_for(id)
          end

          PartnerTokens::Registry::PARTNERS.each_key do |id|
            targets[id] |= PartnerTokens::Registry.enabled_targets_for(id) # [] if the partner is disabled
          end

          targets.reject { |_, t| t.empty? }.to_h { |id, t| [id, analyzer_label(id, t)] }
        end

        def analyzer_label(id, targets)
          return BOTH if targets.sort == Scanners::ALL.sort
          return GSS if targets == [Scanners::GSS]

          raise ArgumentError, "No docs label for scanners of #{id}: #{targets.inspect}"
        end

        def validate_header!(cells)
          return if cells.values_at(ID_CELL, VALIDITY_CELL, ANALYZER_CELL).map(&:strip) ==
            ['ID', 'Validity check', 'Validity check analyzer']

          raise ArgumentError, 'Table columns moved. Update the cell indexes in ValidityCheckDocs.'
        end
      end
    end
  end
end
