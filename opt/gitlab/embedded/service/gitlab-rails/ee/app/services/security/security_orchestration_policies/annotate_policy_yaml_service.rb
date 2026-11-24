# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class AnnotatePolicyYamlService
      NOT_FOUND_STRING = 'not_found'
      ANNOTATION_RULES = {
        users: {
          annotation_method: :username,
          finder: ->(current_user, ids) {
            ::UsersFinder.new(current_user, id: ids)
          }
        },
        user_approvers_ids: {
          alias_key: :users
        },
        groups: {
          annotation_method: :full_path,
          finder: ->(current_user, ids) {
            ::GroupsFinder.new(current_user, ids: ids)
          }
        },
        group_approvers_ids: {
          alias_key: :groups
        },
        block_group_branch_modification: {
          alias_key: :groups
        },
        projects: {
          annotation_method: :full_path,
          finder: ->(current_user, ids) {
            ::ProjectsFinder.new(current_user: current_user, project_ids_relation: ids)
          }
        },
        role_approvers: {
          annotation_method: :name,
          finder: ->(current_user, ids) {
            ::MemberRoles::RolesFinder.new(current_user, id: ids)
          }
        },
        compliance_frameworks: {
          annotation_method: :name,
          finder: ->(current_user, ids) {
            ::ComplianceManagement::FrameworksFinder.new(current_user, ids: ids)
          }
        }
      }.freeze

      KEY_LINE_REGEX = /^\s*(#{Regexp.union(ANNOTATION_RULES.keys.map { |k| Regexp.escape(k.to_s) })}):\s*$/
      ID_LINE_REGEX = /^\s*-\s*(?:id:\s*)?(\d+)\s*$/ # Matches lines with IDs, e.g., "- 123" or "- id: 123"

      def initialize(current_user, policy_yaml)
        @current_user = current_user
        @policy_yaml = policy_yaml
      end

      def execute
        annotated_yaml = annotate_yaml_inline

        ServiceResponse.success(payload: { annotated_yaml: annotated_yaml })
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, policy_yaml: policy_yaml)
        ServiceResponse.error(message: "Unexpected error while annotating policy YAML", payload: { exception: e })
      end

      private

      attr_reader :current_user, :policy_yaml

      def annotate_yaml_inline
        ids_by_key = extract_ids_from_yaml
        fetched_records_by_key = fetch_all_records(ids_by_key)

        lines = []
        scan_yml_lines_for_ids do |line_content, current_key, id|
          if current_key && id
            annotation_value = fetched_records_by_key.dig(current_key, id)
            lines << annotate_line(line_content, annotation_value)
          else
            lines << line_content
          end
        end

        lines.join
      end

      def extract_ids_from_yaml
        Hash.new { |hash, key| hash[key] = Set.new }.tap do |result|
          scan_yml_lines_for_ids do |_line, key, id|
            result[key] << id if key && id
          end
        end
      end

      def scan_yml_lines_for_ids
        current_key = nil
        base_indent = -1

        reset_key_context = proc do
          current_key = nil
          base_indent = -1
        end

        policy_yaml.each_line do |line_content|
          indent = line_content[/^\s*/].size

          if line_content =~ KEY_LINE_REGEX
            current_key = resolve_rule_key(Regexp.last_match(1).to_sym)
            base_indent = indent
          elsif current_key && indent >= base_indent
            if line_content =~ ID_LINE_REGEX
              id = Regexp.last_match(1).to_i
              yield(line_content, current_key, id)
              next
            elsif indent > base_indent || line_content.strip.start_with?('-')
              # maintain the current key if the line is indented more than the base indent
              # or starts with a hyphen (indicating a list item)
            else
              reset_key_context.call
            end
          else
            reset_key_context.call
          end

          yield(line_content, current_key, nil)
        end
      end

      def annotate_line(original_line_content, annotation_value)
        annotation_string = annotation_value || NOT_FOUND_STRING
        "#{original_line_content.rstrip} # #{annotation_string}\n"
      end

      def fetch_all_records(ids_by_key)
        ids_by_key.each_with_object({}) do |(key, ids), records_by_key|
          next if ids.empty?

          records_by_key[key] = fetch_records(key, ids.to_a)
        end
      end

      def fetch_records(key, ids)
        return {} if ids.empty?

        rule_config = resolve_annotation_rule(key)
        finder_instance = rule_config[:finder].call(current_user, ids)
        records = finder_instance.execute

        records.each_with_object({}) do |record, result|
          result[record.id] = record.public_send(rule_config[:annotation_method]) # rubocop:disable GitlabSecurity/PublicSend  -- controlled by ANNOTATION_RULES
        end
      end

      def resolve_rule_key(key)
        ANNOTATION_RULES.dig(key, :alias_key) || key
      end

      def resolve_annotation_rule(key)
        target_key = resolve_rule_key(key)

        ANNOTATION_RULES[target_key]
      end
    end
  end
end
