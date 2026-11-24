# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Base
        PLACEHOLDER = /%\{(\w+)\}/

        DEFAULT_MENTION_TEMPLATE = <<~GOAL.strip
          Input: %{user_input}
          Context: {%{resource_type} %{id_type}: %{id_value}}
        GOAL

        TRIGGER_GOAL_TEMPLATE = <<~GOAL.strip
          <trigger_instructions>
          %{trigger_goal}
          </trigger_instructions>
        GOAL

        TRIGGER_GOAL_TAG = %r{<\s*/?\s*trigger_instructions\s*>}i

        # Raised when a flow's templates have no goal for the event or action a trigger fired on.
        UnsupportedEventError = Class.new(ArgumentError)

        def self.resolve(event_type:, resource:, user_input:, params: {})
          raise NotImplementedError, "#{name} must implement .resolve"
        end

        def self.default_mention_goal(resource:, user_input:)
          resource_type = resource.class.name.demodulize
          id_type, id_value = resource.respond_to?(:iid) ? ['IID', resource.iid] : ['ID', resource.id]

          interpolate(DEFAULT_MENTION_TEMPLATE,
            vars: {
              resource_type: resource_type,
              id_type: id_type,
              id_value: id_value
            },
            user_input: user_input
          )
        end

        # Prepended after the event template has rendered, so a %{...} sequence in the
        # configured goal is never re-interpreted. Both sides lose the tag, so neither the
        # owner nor someone commenting can forge a second instruction block.
        def self.with_trigger_goal(goal, trigger_goal)
          return goal if trigger_goal.blank?

          block = interpolate(TRIGGER_GOAL_TEMPLATE,
            vars: { trigger_goal: strip_trigger_tags(trigger_goal) })

          # The separator is unconditional so the overhead stays the same whatever the
          # derived goal is. resolve_goal measures it by rendering an empty one.
          "#{block}\n\n#{strip_trigger_tags(goal)}"
        end

        # Removal, never escaping: resolve_goal budgets the thread against yield(''), so a
        # transform that grows the text can overflow GOAL_MAX_LENGTH when it re-renders.
        # Loops because one pass rejoins a nested tag: <trigger<trigger_instructions>_instructions>.
        def self.strip_trigger_tags(text)
          out = text.to_s
          out = out.gsub(TRIGGER_GOAL_TAG, '') while out.match?(TRIGGER_GOAL_TAG)
          out
        end

        # Stands in for the raw event input outside a mention, where that input is an
        # iid or a webhook payload rather than anything a flow can read, or is absent
        # entirely on a cron tick.
        def self.trigger_context(resource:, project:, action: nil)
          subject = if resource
                      "#{resource.class.name.demodulize}: #{Gitlab::UrlBuilder.build(resource)}"
                    else
                      "Project: #{Gitlab::UrlBuilder.build(project)}"
                    end

          lines = [subject]
          # merge_request and work_item fold several actions onto one event type, so the
          # action is the only thing that tells one firing from another.
          lines << "Action: #{action}" if action.present?

          "Context:\n#{lines.join("\n")}"
        end

        # Fills every placeholder in one pass, so a filled-in value is never
        # scanned again. A value containing %{user_input} stays literal text.
        # Unknown %{...} is kept as-is. The gsub block form keeps sequences
        # like \& in values as plain text instead of regex replacements.
        def self.interpolate(template, vars:, user_input: nil)
          replacements = vars.transform_keys(&:to_s)
          replacements['user_input'] = user_input unless user_input.nil?

          template.gsub(PLACEHOLDER) do
            key = Regexp.last_match(1)
            replacements.key?(key) ? replacements[key].to_s : Regexp.last_match(0)
          end
        end
      end
    end
  end
end
