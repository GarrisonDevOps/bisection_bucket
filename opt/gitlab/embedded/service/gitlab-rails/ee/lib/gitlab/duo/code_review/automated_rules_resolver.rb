# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      class AutomatedRulesResolver
        RULE_VALUE_READERS = {
          'target_branches' => ->(merge_request) { merge_request.target_branch },
          'source_branches' => ->(merge_request) { merge_request.source_branch },
          'authors' => ->(merge_request) { merge_request.author&.username }
        }.freeze
        VALID_RULE_KEYS = RULE_VALUE_READERS.keys.freeze

        def initialize(project, current_user)
          @project = project
          @current_user = current_user
        end

        def excluded?(merge_request)
          rules = fetch_all_rules(project.default_branch_or_main)

          matches?(merge_request, rules)
        end

        private

        attr_reader :project, :current_user

        def fetch_all_rules(ref)
          fetch_instance
            .merge(fetch_ancestor_groups_rules)
            .merge(fetch_project(ref))
        end

        def fetch_project(ref)
          parse_repo_file(project, ref, :project)
        end

        def fetch_ancestor_groups_rules
          ancestor_duo_template_projects.uniq.each_with_object({}) do |template_project, acc|
            rules = parse_repo_file(template_project, template_project.default_branch_or_main, :group)
            acc.merge!(rules) { |_key, old, new| old + new }
          end
        end

        def fetch_instance
          return {} if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          template_project = ::Gitlab::CurrentSettings.current_application_settings.duo_template_project
          return {} unless template_project

          parse_repo_file(template_project, template_project.default_branch_or_main, :instance)
        end

        def ancestor_duo_template_projects
          return [] unless project.group

          project
            .group
            .self_and_ancestors(hierarchy_order: :asc)
            .with_duo_template_project
            .map { |group| group.namespace_template_setting.duo_template_project }
        end

        def parse_repo_file(project, ref, type)
          raw_rules = project.repository.code_review_automated_rules_for(ref)

          return {} unless raw_rules

          yaml_content = Gitlab::Config::Loader::Yaml.new(raw_rules).load_raw!

          normalize_rules(yaml_content['exclude'])
        rescue StandardError => e
          track_exception(e, project, type: type, ref: ref)

          {}
        end

        def normalize_rules(rules)
          return {} unless rules.is_a?(Hash)

          VALID_RULE_KEYS.each_with_object({}) do |key, normalized_rules|
            patterns = string_patterns(rules[key])
            normalized_rules[key] = patterns if patterns.any?
          end
        end

        def string_patterns(value)
          values = value.is_a?(Array) ? value : [value]

          values.filter_map do |pattern|
            pattern.to_s unless pattern.nil? || pattern.is_a?(Array) || pattern.is_a?(Hash)
          end
        end

        def matches?(merge_request, rules)
          RULE_VALUE_READERS.any? do |rule_key, value_reader|
            value = value_reader.call(merge_request)

            rules.fetch(rule_key, []).any? { |pattern| wildcard_match?(pattern, value) }
          end
        end

        def wildcard_match?(pattern, value)
          return false if value.nil?

          File.fnmatch(pattern, value)
        end

        def track_exception(error, project, **extra_data)
          Gitlab::ErrorTracking.track_exception(error, project_id: project.id, **extra_data)
        end
      end
    end
  end
end
