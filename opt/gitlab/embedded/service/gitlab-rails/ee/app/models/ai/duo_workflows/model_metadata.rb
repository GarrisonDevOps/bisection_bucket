# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Maps raw `model_used` values to model catalog metadata for the `model`
    # dimension. Rows may carry a gateway ref (`claude_sonnet_4_5`), a display
    # name, or the provider-resolved id billing records
    # (`us.anthropic.claude-haiku-4-5-20251001-v1:0`).
    class ModelMetadata
      # `id` is the value the row was grouped by, so the same model pairs across
      # periods. `model_key` is the hosting-neutral key for the alias dictionary,
      # `nil` when nothing matches so a catalog outage never replaces a resolved mapping.
      Entry = Struct.new(:id, :model_key, :name, :provider, :hosting, :is_default, keyword_init: true)

      # The catalog's pseudo-entry for default-routed traffic; its actual host
      # varies per request, so it never gets a provider.
      ROUTED_REF_PREFIX = '__default__'

      SELF_HOSTED_KEY = 'self_hosted'

      # Self-hosted keys carry the record id, so a configured model never
      # merges with a catalog model that happens to share its name.
      SELF_HOSTED_KEY_PREFIX = "#{SELF_HOSTED_KEY}/".freeze

      # The gateway bills every self-hosted call under this placeholder,
      # whichever configured model served it, so it can never name a record.
      SELF_HOSTED_PLACEHOLDER = 'self-hosted-model'

      HOSTED_REF = /_(vertex|bedrock)\z/

      # Refs and served ids disagree on snapshot dates: `claude_opus_4_6_20260205`
      # is served as `claude-opus-4-6`, and an undated alias can come back dated.
      DATE_SEGMENT = /_\d{8}(?=_|\z)/

      def self.for(raw_values)
        new(raw_values).to_h
      end

      def initialize(raw_values)
        @raw_values = raw_values
      end

      def to_h
        @raw_values.index_with { |value| entry_for(value.to_s).tap { |entry| entry.id = value.to_s } }
      end

      def catalog_available?
        !parser.nil?
      end

      private

      def entry_for(raw)
        return Entry.new(model_key: nil, name: nil, provider: nil, hosting: nil, is_default: false) if raw.empty?

        return self_hosted_entry(SELF_HOSTED_KEY) if raw == SELF_HOSTED_PLACEHOLDER

        # The model dimension groups by alias key, so keys arrive here too. A key
        # wins over a self-hosted model spelled like it, or one configured model
        # would take over every row grouped under that key.
        return self_hosted_entry(raw) if self_hosted_key?(raw)

        self_hosted = self_hosted_match(raw) unless catalog_ref?(raw)
        matches = catalog_matches(raw)
        match = matches.first
        twin_key = twin_key?(raw, match)

        name = self_hosted&.name || (match ? stripped_name(match) : raw)

        Entry.new(
          model_key: model_key_for(self_hosted, match),
          name: name,
          provider: (provider_for(matches) unless self_hosted || twin_key),
          hosting: self_hosted ? :self_hosted : :gitlab,
          is_default: default?(twin_key ? twins_of(match) : matches)
        )
      end

      def provider_for(matches)
        match = matches.first
        match[:model_provider] if match && matches.one? && !routed?(match)
      end

      def self_hosted_key?(raw)
        raw == SELF_HOSTED_KEY || raw.start_with?(SELF_HOSTED_KEY_PREFIX)
      end

      def catalog_ref?(raw)
        catalog_by_ref.key?(raw)
      end

      def self_hosted_entry(key)
        record = self_hosted_models.find { |model| "#{SELF_HOSTED_KEY_PREFIX}#{model.id}" == key }

        Entry.new(
          model_key: key, name: record&.name || s_('DuoWorkflow|Self-hosted model'), provider: nil,
          hosting: :self_hosted, is_default: false
        )
      end

      # An alias key stands for its whole twin set, so it has no single
      # provider and is a default when any twin is.
      def twin_key?(raw, match)
        return false unless match && raw == match[:ref] && !routed?(match)

        twins_of(match).many? && catalog_key_for(match) == raw
      end

      def model_key_for(self_hosted, match)
        return "#{SELF_HOSTED_KEY_PREFIX}#{self_hosted.id}" if self_hosted

        catalog_key_for(match) if match
      end

      # Prefers a ref without a host suffix, then the shortest: a dated bare ref
      # (`claude_opus_4_6_20260205`) can outrun `claude_opus_4_6_vertex` on
      # length alone. Routed default traffic is no twin of a real model, so it
      # keeps its own key.
      def catalog_key_for(match)
        return match[:ref] if routed?(match)

        twins_of(match).map { |model| model[:ref] }
          .min_by { |ref| [HOSTED_REF.match?(ref) ? 1 : 0, ref.length, ref] }
      end

      def routed?(model)
        model[:ref].to_s.start_with?(ROUTED_REF_PREFIX)
      end

      def catalog_matches(raw)
        matches = catalog.select do |model|
          model[:ref] == raw || model[:name] == raw || stripped_name(model) == raw
        end
        return matches if matches.any?

        base, host = normalize(raw)
        return [] if base.empty?

        anchor = (host && find_ref("#{base}_#{host}")) || find_ref(base)
        return [] unless anchor

        # A host-qualified id pins one entry. A bare id cannot tell hosting
        # twins apart, so all of them match and provider stays ambiguous.
        host ? [anchor] : twins_of(anchor)
      end

      def twins_of(anchor)
        catalog.select { |model| stripped_name(model) == stripped_name(anchor) }
      end

      # Resolved ids spell the model with dots and dashes plus a region prefix
      # and version suffix; catalog refs use underscores with a host suffix.
      # Bedrock ids (`bedrock/` or region-prefixed, versioned) and Vertex ids
      # (`@date`) are self-describing, so they prefer their host's ref.
      def normalize(raw)
        value = raw.downcase.delete_prefix('bedrock/')
        host = if value.match?(/\A(us|eu|apac|global)\.anthropic\./) || value.include?(':')
                 'bedrock'
               elsif value.include?('@')
                 'vertex'
               end

        base = value
          .sub(/\A(us|eu|apac|global)\./, '')
          .delete_prefix('anthropic.')
        # Only Bedrock ids carry a strip-worthy version suffix; a bare `-vN`
        # elsewhere is part of the model's identity.
        base = base.sub(/-v\d+(:\d+)?\z/, '') if host == 'bedrock'
        [base.gsub(/[-.@]/, '_'), host]
      end

      # The gateway bakes the hosting provider into the name
      # ("Claude Sonnet 4.5 - Bedrock").
      def stripped_name(model)
        name = model[:name].to_s
        provider = model[:model_provider].to_s
        suffix = " - #{provider}"
        provider.present? && name.end_with?(suffix) ? name.delete_suffix(suffix) : name
      end

      # Tiered so several configured models never resolve arbitrarily: a
      # non-blank identifier is the only key an admin controls per record, a
      # name is unique, and the bare family string is a last resort. Lowest
      # id wins within a tier.
      def self_hosted_match(raw)
        by_identifier = self_hosted_models.select do |model|
          model.identifier.present? && model.identifier.casecmp?(raw)
        end
        by_name = self_hosted_models.select { |model| model.name.to_s.casecmp?(raw) }
        by_family = self_hosted_models.select { |model| model.model.to_s.casecmp?(raw) }

        (by_identifier.presence || by_name.presence || by_family.presence)&.min_by(&:id)
      end

      # Compared by ref: hosting twins share a stripped display name, so a
      # name comparison would flag the default's twin too.
      def default?(matches)
        matches.any? { |model| default_refs.include?(model[:ref]) }
      end

      # Rows span chat and non-chat flows, which default through different
      # features, so both feature's defaults count. With several default
      # models the gateway's singular field is a `__default__` pseudo ref no
      # real row can carry; `default_models` lists the real refs. The pseudo
      # ref stays in the set so default-routed rows flag too.
      def default_refs
        @default_refs ||= [
          ::Ai::ModelSelection::FeaturesConfigurable.agentic_chat_feature_name,
          ::Ai::ModelSelection::FeaturesConfigurable.workflow_feature_name
        ].flat_map { |feature| default_refs_for(feature) }.uniq
      end

      def default_refs_for(feature)
        # No safe navigation: a catalog match precedes every call, so the
        # parser is present here.
        definition = parser.definition_for_feature(feature)
        return [] unless definition

        [definition['default_model'], *definition['default_models']].compact
      end

      def catalog
        @catalog ||= parser&.gitlab_models_by_ref&.values || []
      end

      def catalog_by_ref
        @catalog_by_ref ||= catalog.index_by { |model| model[:ref] }
      end

      def find_ref(ref)
        catalog_by_ref[ref] || catalog_by_undated_ref[undated(ref)]
      end

      # Shortest ref wins a collision so the lookup does not depend on catalog order.
      def catalog_by_undated_ref
        @catalog_by_undated_ref ||= catalog
          .group_by { |model| undated(model[:ref].to_s) }
          .transform_values { |models| models.min_by { |model| [model[:ref].length, model[:ref]] } }
      end

      def undated(ref)
        ref.gsub(DATE_SEGMENT, '')
      end

      def parser
        return @parser if defined?(@parser)

        @parser = ::Ai::ModelSelection::ModelDefinitions.fetch.parser
      end

      def self_hosted_models
        @self_hosted_models ||= ::Ai::SelfHostedModel.all.to_a
      end
    end
  end
end
