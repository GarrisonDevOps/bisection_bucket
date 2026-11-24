# frozen_string_literal: true

module Gitlab
  module Security
    module Parsers
      class Sarif
        module IdentifierExtractor
          CVE_RE = /\ACVE-\d{4}-\d+\z/i
          CWE_RE = /\ACWE-?(\d+)\z/i
          CWE_RELATIONSHIP_ID_RE = /\A(?:CWE-?)?(\d+)\z/i
          TAG_RE = /\A(cwe|cve)[:-]([A-Z0-9-]+)/i

          class << self
            def semantic_identifiers(result:, rule:)
              ids = []
              ids.concat(from_rule_id(result['ruleId'] || result.dig('rule', 'id')))
              ids.concat(from_tags(rule.dig('properties', 'tags')))
              ids.concat(from_relationships(rule['relationships']))
              ids.uniq { |id| [id[:type], id[:number]] }
            end

            def from_rule_id(rule_id)
              return [] if rule_id.nil?

              if rule_id.match?(CVE_RE)
                upper = rule_id.upcase
                bare  = upper.delete_prefix('CVE-')
                return [{ type: :cve, value: upper, number: bare, external_id: bare, raw: rule_id }]
              end

              match = rule_id.match(CWE_RE)
              if match
                return [{ type: :cwe, value: "CWE-#{match[1]}", number: match[1], external_id: match[1], raw: rule_id }]
              end

              []
            end

            def from_tags(tags)
              Array(tags).filter_map do |tag|
                match = tag.match(TAG_RE)
                next unless match

                type = match[1].downcase
                raw_tail = match[2]

                case type
                when 'cwe'
                  next unless raw_tail.match?(/\A\d+\z/)

                  { type: :cwe, value: "CWE-#{raw_tail}", number: raw_tail, external_id: raw_tail, raw: tag }
                when 'cve'
                  bare = raw_tail.upcase.delete_prefix('CVE-')
                  next unless CVE_RE.match?("CVE-#{bare}")

                  { type: :cve, value: "CVE-#{bare}", number: bare, external_id: bare, raw: tag }
                end
              end
            end

            def from_relationships(relations)
              Array(relations).filter_map do |relation|
                next unless relation.is_a?(Hash)

                target_name = relation.dig('target', 'toolComponent', 'name').to_s
                next unless target_name.casecmp('CWE') == 0

                id    = relation.dig('target', 'id').to_s
                match = id.match(CWE_RELATIONSHIP_ID_RE)
                next unless match

                { type: :cwe, value: "CWE-#{match[1]}", number: match[1], external_id: match[1], raw: id }
              end
            end
          end
        end
      end
    end
  end
end
