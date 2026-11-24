# frozen_string_literal: true

module Gitlab
  module CodeOwners
    class SectionParser
      include Gitlab::Utils::StrongMemoize

      REGEX = {
        bol: %r{^}.source,
        optional: %r{(?<optional>\^)?}.source,
        name: %r{\[(?<name>.*?)\]}.source,
        approvals: %r{(?:\[(?<approvals>[\s\d]*)\])?}.source,
        default_owners: %r{(?<default_owners>\s*[@\w.\-/\s]*)?}.source,
        strict_name: %r{(?<name>\[[^\]]+\])}.source,
        strict_approvals: %r{(?<approvals>\[\d+\])?}.source,
        strict_default_owners: %r{(?<default_owners>\s+[@\w\.\-/\s]+)?}.source,
        opening_bracket: %r{\[}.source,
        eol: %r{$}.source
      }.freeze

      HEADER_REGEX = Regexp.new(REGEX.values_at(:bol, :optional, :name, :approvals, :default_owners).join)
      STRICT_HEADER_REGEX = Regexp.new(
        REGEX.values_at(:bol, :optional, :strict_name, :strict_approvals, :strict_default_owners, :eol).join
      )
      INVALID_SECTION_REGEX = Regexp.new(REGEX.values_at(:bol, :optional, :opening_bracket).join)
      STRING_INTEGER_REGEX = %r{^\s*\d+\s*$}

      def initialize(line, sectional_data, line_number)
        @line = line
        @sectional_data = sectional_data
        @line_number = line_number
        @errors = Errors.new
        parse_section
      end

      attr_reader :errors, :section

      def section_header?
        section.present?
      end

      def unparsable_section_header?
        return false if section_header?

        line.match?(INVALID_SECTION_REGEX)
      end
      strong_memoize_attr :unparsable_section_header?

      def valid?
        errors.none?
      end

      private

      attr_reader :line, :sectional_data, :line_number

      def parse_section
        match = line.match(HEADER_REGEX)
        if match
          @section = Section.new(
            name: find_section_name(match[:name]),
            optional: match[:optional].present?,
            raw_approvals: match[:approvals],
            approvals: match[:approvals].to_i,
            default_owners: match[:default_owners]
          )
        end

        validate_section
      end

      def validate_section
        errors.add(:invalid_section_format, line_number) if unparsable_section_header?

        return unless section_header?

        errors.add(:missing_section_name, line_number) if missing_section_name?
        errors.add(:invalid_approval_requirement, line_number) if invalid_approvals?
        errors.add(:invalid_section_owner_format, line_number) if invalid_default_owners?
        errors.add(:invalid_section_format, line_number) if invalid_strict_section?
      end

      def find_section_name(name)
        section_headers = sectional_data.keys

        return name if section_headers.last == Section::DEFAULT

        section_headers.find { |k| k.casecmp?(name) } || name
      end

      def invalid_strict_section?
        return if errors.any?

        !line.match?(STRICT_HEADER_REGEX)
      end

      def missing_section_name?
        section.name.blank?
      end

      def invalid_default_owners?
        return false if section.default_owners.blank?

        default_owners = section.default_owners.split
        found_references = ReferenceExtractor.new(section.default_owners).raw_references
        missing_references = default_owners - found_references
        missing_references.any?
      end

      def invalid_approvals?
        return false if section.raw_approvals.nil?
        return true unless section.raw_approvals.match?(STRING_INTEGER_REGEX)

        section.optional && section.approvals > 0
      end
    end
  end
end
