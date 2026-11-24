# frozen_string_literal: true

module Gitlab
  module Ai
    module Catalog
      module Skills
        # The one ruleset for whether a SKILL.md is publishable: the Agent Skills specification
        # (https://agentskills.io/specification) plus GitLab's own limits. Takes content and a
        # path, never a repository, so every validation point can call it.
        class Validator
          include ::Gitlab::Utils::Executable

          SCHEMA_PATH = Rails.root.join('app/validators/json_schemas/ai_catalog/skill_frontmatter_v1.json')

          # GitLab's limits for the item Definition. The specification sets none for these fields,
          # so they stay out of the vendored schema and are reported as platform rejections.
          PLATFORM_MAX_LENGTHS = { 'license' => 255, 'allowed-tools' => 1024 }.freeze

          # Abuse limits, far above what the specification's fields need. Psych builds Ruby objects
          # recursively, so deep nesting overflows the stack well inside the size limit.
          MAX_FRONT_MATTER_BYTES = 16.kilobytes
          MAX_FRONT_MATTER_DEPTH = 20

          # `category` is :spec for a specification rule, which an author can act on anywhere, or
          # :platform for a GitLab limit, which only means anything inside GitLab.
          Rejection = Data.define(:path, :code, :message, :category)

          Result = Data.define(:path, :attributes, :rejections) do
            def valid?
              rejections.empty?
            end
          end

          # Counts nesting from parse events, which libyaml emits without recursing.
          class DepthCheck < Psych::Handler
            TooDeep = Class.new(StandardError)

            def initialize(max_depth)
              @max_depth = max_depth
              @depth = 0
            end

            def start_mapping(...)
              descend
            end

            def start_sequence(...)
              descend
            end

            def end_mapping
              @depth -= 1
            end

            def end_sequence
              @depth -= 1
            end

            private

            def descend
              @depth += 1
              raise TooDeep if @depth > @max_depth
            end
          end
          private_constant :DepthCheck

          def self.schema
            # ECMA semantics, as JSON Schema intends: Ruby's ^ and $ would let `name` span lines.
            @schema ||= JSONSchemer.schema(SCHEMA_PATH, regexp_resolver: 'ecma')
          end

          # @param path [String] path of the SKILL.md, used to check `name` against its directory
          # @param content [String] full contents of the SKILL.md
          def initialize(path:, content:)
            @path = path.to_s
            @content = content.to_s
          end

          # @return [Result] attributes are nil unless the skill is valid
          def execute
            front_matter = yaml_front_matter
            return failure([no_frontmatter_rejection]) unless front_matter
            return failure([too_large_rejection]) if front_matter.bytesize > MAX_FRONT_MATTER_BYTES
            return failure([too_deep_rejection]) if too_deep?(front_matter)

            fields = parse_yaml(front_matter)
            return failure([invalid_yaml_rejection]) if fields.nil?
            return failure([not_a_mapping_rejection]) unless fields.is_a?(Hash)

            rejections = schema_rejections(fields) + platform_rejections(fields) + directory_rejections(fields)
            return failure(rejections) if rejections.any?

            Result.new(path: path, attributes: attributes(fields), rejections: [])
          end

          private

          attr_reader :path, :content

          # The shared front matter pattern also matches TOML and JSON blocks, which the
          # specification does not allow.
          def yaml_front_matter
            match = ::Gitlab::FrontMatter::PATTERN_UNTRUSTED_REGEX.match(content)
            return unless match && match[:delim] == '---' && match[:lang].blank?

            match[:front_matter]
          end

          # A syntax error is left for parse_yaml to report as invalid_yaml.
          def too_deep?(front_matter)
            Psych::Parser.new(DepthCheck.new(MAX_FRONT_MATTER_DEPTH)).parse(front_matter)
            false
          rescue DepthCheck::TooDeep
            true
          rescue Psych::SyntaxError
            false
          end

          # @return [Object, nil] nil when the YAML cannot be parsed
          def parse_yaml(front_matter)
            fields = YAML.safe_load(front_matter, permitted_classes: [Date, Time])
            # Empty front matter loads as nil; {} reports each missing field instead.
            fields.nil? ? {} : fields
          rescue Psych::Exception, ArgumentError # a bad explicit tag, such as `!!float x`, raises ArgumentError
            nil
          end

          def schema_rejections(fields)
            self.class.schema.validate(fields).flat_map do |error|
              next missing_field_rejections(error) if error['type'] == 'required'

              segments = pointer_segments(error['data_pointer'])
              rejection(code_for(segments.first), schema_message(error, segments))
            end
          end

          def missing_field_rejections(error)
            error.dig('details', 'missing_keys').map do |field|
              rejection(code_for(field), format(s_('FrontMatterValidation|%{field} is required.'), field: field))
            end
          end

          def platform_rejections(fields)
            PLATFORM_MAX_LENGTHS.filter_map do |field, max|
              value = fields[field]
              next unless value.is_a?(String) && value.length > max

              rejection(code_for(field), max_length_message(field, max), category: :platform)
            end
          end

          # A JSON schema cannot compare the document with its file path, so this rule lives here.
          # Skipped when `name` is absent or not text, which the schema has already reported.
          def directory_rejections(fields)
            name = fields['name']
            directory = File.basename(File.dirname(path))
            return [] if !name.is_a?(String) || name == directory

            message = format(
              s_('AICatalogSkillValidation|name must match the parent directory name, %{directory}.'),
              directory: directory
            )

            [rejection(:name_directory_mismatch, message)]
          end

          def attributes(fields)
            {
              'name' => fields['name'],
              'description' => fields['description'],
              'license' => fields['license'],
              'compatibility' => fields['compatibility'],
              'allowed_tools' => fields['allowed-tools'],
              'metadata' => fields['metadata'] || {}
            }.compact
          end

          # Keyed on the top-level field only: below `metadata` the keys are the author's own, and
          # a code that varies with user input is useless to anything matching on it.
          def code_for(field)
            field ? :"invalid_#{field.tr('-', '_')}" : :invalid_frontmatter
          end

          # Limits are read from the failing subschema, so changing the schema changes the message.
          def schema_message(error, segments)
            field = segments.join('.')
            schema = error['schema']

            case error['type']
            when 'maxLength'
              max_length_message(field, schema['maxLength'])
            when 'minLength'
              min_length_message(field, schema['minLength'])
            when 'pattern'
              segments == ['name'] ? name_pattern_message : invalid_field_message(field)
            when 'string'
              return empty_field_message(field) if error['data'].nil?

              format(s_('FrontMatterValidation|%{field} must be text.'), field: field)
            when 'object'
              format(s_('FrontMatterValidation|%{field} must be a mapping.'), field: field)
            else
              invalid_field_message(field)
            end
          end

          def max_length_message(field, max)
            format(s_('FrontMatterValidation|%{field} must be %{max} characters or fewer.'), field: field, max: max)
          end

          def min_length_message(field, min)
            return empty_field_message(field) if min == 1

            format(s_('FrontMatterValidation|%{field} must be at least %{min} characters.'), field: field, min: min)
          end

          def empty_field_message(field)
            format(s_('FrontMatterValidation|%{field} must not be empty.'), field: field)
          end

          def invalid_field_message(field)
            return s_('FrontMatterValidation|The YAML front matter is not valid.') if field.empty?

            format(s_('FrontMatterValidation|%{field} is not valid.'), field: field)
          end

          def name_pattern_message
            s_(
              'AICatalogSkillValidation|name must contain only lowercase letters, numbers, and hyphens. ' \
                'It cannot start or end with a hyphen, or contain two hyphens in a row.'
            )
          end

          # RFC 6901 escapes `/` and `~` in keys, which would otherwise leak into messages.
          def pointer_segments(pointer)
            pointer.to_s.split('/').drop(1).map { |segment| segment.gsub('~1', '/').gsub('~0', '~') }
          end

          def no_frontmatter_rejection
            rejection(
              :no_frontmatter,
              s_('AICatalogSkillValidation|SKILL.md must start with YAML front matter between --- lines.')
            )
          end

          def too_large_rejection
            message = format(
              s_('AICatalogSkillValidation|The YAML front matter must be %{size} or smaller.'),
              size: ActiveSupport::NumberHelper.number_to_human_size(MAX_FRONT_MATTER_BYTES)
            )

            rejection(:frontmatter_too_large, message, category: :platform)
          end

          def too_deep_rejection
            rejection(
              :frontmatter_too_deep,
              s_('AICatalogSkillValidation|The YAML front matter is nested too deeply.'),
              category: :platform
            )
          end

          def invalid_yaml_rejection
            rejection(:invalid_yaml, s_('FrontMatterValidation|The YAML front matter could not be parsed.'))
          end

          def not_a_mapping_rejection
            rejection(
              :frontmatter_not_a_mapping,
              s_('FrontMatterValidation|The YAML front matter must be a mapping of fields.')
            )
          end

          def rejection(code, message, category: :spec)
            Rejection.new(path: path, code: code, message: message, category: category)
          end

          def failure(rejections)
            Result.new(path: path, attributes: nil, rejections: rejections)
          end
        end
      end
    end
  end
end
