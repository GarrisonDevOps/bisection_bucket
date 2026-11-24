# frozen_string_literal: true

# Documents Grape cross-field param validations by appending a note to each
# affected parameter's / request-body property's description.
#
# OpenAPI 3.0 has no cross-parameter keyword and Scalar (the renderer) does not
# render JSON Schema `not`/`allOf`, so these constraints are stated in prose;
# Grape enforces them at runtime (HTTP 400).
#
# Each cross-field validator is a CONSTRAINTS entry pairing the validator class
# names it carries across supported Grape versions (Grape 3.2 renamed one)
# with a note strategy. A strategy receives every group of its kind found on the
# route (each group an array of top-level attribute-name strings) and returns
# `{ param => note }`.
#
# The validations read and the Grape 2.x/3.2 shape difference are isolated in
# GrapeCompat.

module Gitlab
  module GrapeOpenapi
    module Converters
      class CrossFieldValidationResolver
        GROUP_SENTENCE = lambda do |lead|
          lambda do |groups|
            groups.each_with_object({}) do |group, result|
              note = "#{lead} #{group.map { |name| "`#{name}`" }.join(', ')} must be provided."

              group.each { |name| result[name] = append_note(result[name], note) }
            end
          end
        end

        MUTUALLY_EXCLUSIVE = {
          classes: [
            'Grape::Validations::Validators::MutualExclusionValidator',  # Grape < 3.2
            'Grape::Validations::Validators::MutuallyExclusiveValidator' # Grape >= 3.2
          ].freeze,
          summary_format: 'At most one of %d related parameters may be provided.',
          notes: lambda do |groups|
            partners = Hash.new { |hash, key| hash[key] = [] }

            groups.each do |group|
              group.each do |name|
                (group - [name]).each do |other|
                  partners[name] << other unless partners[name].include?(other)
                end
              end
            end

            partners.transform_values do |others|
              "Mutually exclusive with #{others.map { |name| "`#{name}`" }.join(', ')}."
            end
          end
        }.freeze

        EXACTLY_ONE_OF = {
          classes: [
            'Grape::Validations::Validators::ExactlyOneOfValidator' # Grape all versions
          ].freeze,
          summary_format: 'Exactly one of %d related parameters must be provided.',
          notes: GROUP_SENTENCE.call('Exactly one of')
        }.freeze

        AT_LEAST_ONE_OF = {
          classes: [
            'Grape::Validations::Validators::AtLeastOneOfValidator' # Grape all versions
          ].freeze,
          summary_format: 'At least one of %d related parameters must be provided.',
          notes: GROUP_SENTENCE.call('At least one of')
        }.freeze

        ALL_OR_NONE_OF = {
          classes: [
            'Grape::Validations::Validators::AllOrNoneOfValidator' # Grape all versions
          ].freeze,
          summary_format: '%d related parameters must be provided together, or not at all.',
          notes: GROUP_SENTENCE.call('All or none of')
        }.freeze

        CONSTRAINTS = [MUTUALLY_EXCLUSIVE, EXACTLY_ONE_OF, AT_LEAST_ONE_OF, ALL_OR_NONE_OF].freeze

        # For callers that need notes alone, which is every caller that has no
        # nested scope to skip - see `#notes`.
        def self.notes_for(route, attributes)
          new(route, attributes).notes
        end

        # Appends a note to an existing description so the two read as separate
        # sentences. Returns the note alone when there is no
        # existing text.
        def self.append_note(description, note)
          text = description.to_s.strip
          return note if text.empty?

          text += '.' unless text.end_with?('.', '!', '?')
          "#{text} #{note}"
        end

        # `attributes` are the param names the caller is able to annotate: a
        # route's query params, or a request body's top-level properties. Both
        # readers below share one walk of the route's validations, so a caller
        # that needs both pays for it once.
        def initialize(route, attributes)
          @route = route
          @attributes = attributes
        end

        # Per-param description notes for every cross-field constraint on the
        # route, e.g. { 'files' => 'Mutually exclusive with `content`.' }.
        # Notes from different constraints on the same param are
        # joined. Returns {} when there are none.
        def notes
          @notes ||= matched_entries.each_with_object({}) do |(constraint, entries), result|
            groups = annotatable_groups(entries)
            next if groups.empty?

            constraint[:notes].call(groups).each do |param, note|
              result[param] = self.class.append_note(result[param], note)
            end
          end
        end

        # Constraints whose groups are too big to enumerate
        # Adds configured custom summary or default summary for the entire group
        # rather than one sentence per group member.
        def oversized
          @oversized ||= matched_entries.flat_map do |constraint, entries|
            declared_groups(entries)
              .select { |group| oversized?(group) }
              .map { |group| { summary: format(constraint[:summary_format], group.length), size: group.length } }
          end
        end

        # The groups `notes` could NOT annotate (a member isn't one of `attributes`).
        def skipped
          @skipped ||= matched_entries.flat_map do |_constraint, entries|
            constrained_groups(entries).reject { |group| fully_known?(group) }
          end.uniq
        end

        private

        attr_reader :route, :attributes

        def known_names
          @known_names ||= Array(attributes).map(&:to_s)
        end

        # Groups all validations on the route
        # Returns only validations with classes in CONSTRAINTS:
        # [[MUTUALLY_EXCLUSIVE, [
        #  { validator_class: Grape::Validations::Validators::MutualExclusionValidator,
        #    full_names: ["content", "files"] }
        #  ]]]
        def matched_entries
          @matched_entries ||= begin
            by_validator = GrapeCompat.all_validations(route).group_by { |entry| validator_name(entry) }

            CONSTRAINTS.map do |constraint|
              [constraint, by_validator.values_at(*constraint[:classes]).compact.flatten]
            end
          end
        end

        # Groups whose members are all in the known set. The exact complement of
        # what `skipped` keeps, so both derive from `fully_known?` rather than
        # restating the condition and risking drift.
        def annotatable_groups(entries)
          constrained_groups(entries).select { |group| fully_known?(group) }
        end

        # Groups eligible for a per-param note: declared, and small enough that
        # naming every member reads well.
        def constrained_groups(entries)
          declared_groups(entries).reject { |group| oversized?(group) }
        end

        # Every distinct group a constraint declares. A single-member group
        # constrains nothing - Grape accepts `mutually_exclusive :a` - so it is
        # neither annotated nor reported as skipped.
        def declared_groups(entries)
          entries.map { |entry| group_members(entry) }.uniq.select { |group| group.length >= 2 }
        end

        def oversized?(group)
          group.length > config.cross_field_group_limit
        end

        def config
          @config ||= Gitlab::GrapeOpenapi.configuration
        end

        # Whether the caller can annotate every member of the group.
        def fully_known?(group)
          (group - known_names).empty?
        end

        # eg. => 'Grape::Validations::Validators::MutuallyExclusiveValidator'
        def validator_name(entry)
          entry[:validator_class]&.name
        end

        # Full bracketed paths
        # top level eg. ["author_id", "author_username"]
        # nested(nested under `not:`) eg. ["not[author_id]", "not[author_username]"]
        def group_members(entry)
          Array(entry[:full_names]).map(&:to_s)
        end
      end
    end
  end
end
