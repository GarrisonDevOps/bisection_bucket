# frozen_string_literal: true

module Ai
  module ModelSelection
    module ModelAllowlist
      extend ActiveSupport::Concern

      MAX_MODEL_REFS = 100

      included do
        validates :model_allowlist_enabled, inclusion: { in: [true, false] }
        validates :model_allowlist_gitlab_model_refs, length: { maximum: MAX_MODEL_REFS }
        validate :validate_model_allowlist_identifiers
      end

      # Returns true when this feature setting record participates in the
      # admin model allowlist contract. In v1 only Agentic Chat is supported;
      # all other model-selection features fall back to the existing pinned
      # / default behaviour.
      def model_allowlist_supported?
        feature.to_sym == ::Ai::ModelSelection::FeaturesConfigurable.agentic_chat_feature_name
      end

      # Returns the ref of the currently chosen model for this feature, or nil
      # when no model is chosen and no GitLab default is defined.
      #
      # The chosen ref is `offered_model_ref` when present, otherwise the
      # GitLab default model ref resolved from model definitions for the
      # current feature. This makes blank `offered_model_ref` behave as
      # "GitLab default model" rather than "no model".
      def currently_chosen_model_ref(model_definition_parser)
        offered_model_ref.presence || model_definition_parser&.default_model_ref_for_feature(feature)
      end

      # Returns the deduplicated set of refs that are effectively allowed for
      # this feature when the allowlist is enabled.
      #
      # The currently chosen/default model is always implicitly allowed, so
      # the effective set is the union of stored refs and the currently
      # chosen ref, compacted (blank-rejected) and deduplicated. Returns
      # `[]` when the allowlist is disabled.
      def effective_allowed_model_refs(model_definition_parser)
        return [] unless model_allowlist_enabled

        (model_allowlist_gitlab_model_refs + [currently_chosen_model_ref(model_definition_parser)])
          .compact_blank
          .uniq
      end

      # Returns the refs that should be persisted to
      # `model_allowlist_gitlab_model_refs` for an allowlist update.
      #
      # When the allowlist is being disabled, the stored refs are wiped to
      # `[]`. When enabled, submitted refs are:
      #
      # 1. compacted and deduplicated;
      # 2. intersected with the currently selectable refs from model
      #    definitions, so a stale or deprecated ref can never enter the
      #    stored array (and any stale ref present in submitted refs is
      #    silently dropped instead of failing the write);
      # 3. stripped of the currently chosen/default ref, which is allowed
      #    implicitly at read time and does not need to be persisted.
      #
      # When `model_definition_parser` is nil (degraded fetch), the
      # intersection step is skipped so we don't accidentally wipe an
      # otherwise-valid submission.
      def normalize_allowlist_model_refs(submitted_refs, enabled:, model_definition_parser:)
        return [] unless enabled

        normalized = Array(submitted_refs).compact_blank.uniq

        if model_definition_parser
          selectable_refs = model_definition_parser.selectable_model_refs_for_feature(feature)
          normalized &= selectable_refs
        end

        normalized - [currently_chosen_model_ref(model_definition_parser)].compact
      end

      private

      def validate_model_allowlist_identifiers
        return if model_allowlist_gitlab_model_refs.all?(&:present?)

        errors.add(:model_allowlist_gitlab_model_refs, 'must contain non-blank strings')
      end
    end
  end
end
