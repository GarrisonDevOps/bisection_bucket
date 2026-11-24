# frozen_string_literal: true

module WorkItems
  module Decisions
    class UpdateService
      include Gitlab::Utils::StrongMemoize

      UPDATABLE_ATTRIBUTES = %i[
        question description resolution_rationale discussion_id source_link resolved_by_id resolving_note_id
      ].freeze
      RESOLUTION_ATTRIBUTES = %i[resolution_rationale resolved_by_id resolving_note_id selected_option_content].freeze
      OPTION_TEXT_ATTRIBUTES = %i[content description].freeze
      OPTION_FLAG_ATTRIBUTES = %i[selected].freeze

      def initialize(decision:, current_user:, params: {})
        @decision = decision
        @work_item = decision.work_item
        @current_user = current_user
        @params = params
      end

      def execute
        return ServiceResponse.error(message: _('Operation not allowed')) unless allowed?

        response = ApplicationRecord.transaction do
          decision.lock!
          # lock! reloads the decision and drops its cached work_item; reattach it to skip a re-query
          decision.association(:work_item).target = work_item

          error = validate_params
          next ServiceResponse.error(message: error) if error

          options_params.each do |option_params|
            options_by_id[option_params[:id].to_i].update!(option_params.except(:id))
          end

          update_selected_option_content! if selected_option_content_provided?

          decision.update!(update_attributes) if update_attributes.any?

          ServiceResponse.success(payload: { decision: decision })
        end
        return response if response.error?

        track_event

        response
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.record.errors.full_messages.to_sentence)
      end

      private

      attr_reader :decision, :work_item, :current_user, :params

      def validate_params
        return _('Archived decisions cannot be updated') if decision.archived_at?
        return _('No attributes to update') if provided_attributes.empty? && options_params.empty?
        return blank_attributes_error if blank_attributes.any?
        return blank_option_attributes_error if blank_option_attributes.any?

        validate_resolution || validate_options || validate_selected_option_content
      end

      def validate_resolution
        return resolution_attributes_error if resolution_attributes.any? && !decision.resolved_at?
        return _('Resolver must have access to the work item') if resolver_provided? && !valid_resolver?

        _('Note cannot resolve this decision') if resolving_note_provided? && !valid_resolving_note?
      end

      def validate_options
        return if options_params.empty?
        return _('Options must include an attribute to update') if options_params.any? { |o| o.except(:id).empty? }
        return _('Options must be unique') unless option_ids.uniq.size == option_ids.size
        return _('Options must belong to the decision') unless option_ids.all? { |id| options_by_id.key?(id) }
        return _('Selected options can only be updated on resolved decisions') if selecting? && !decision.resolved_at?

        _('Resolution rationale is required when rejecting all options') if rejecting_all_options?
      end

      def validate_selected_option_content
        return unless selected_option_content_provided?

        _('Options and selected option content cannot be updated together') if options_params.any?
      end

      # get_widget covers type registration, ai_workflows licensing, and the
      # decision_log feature flag
      def allowed?
        Ability.allowed?(current_user, :update_work_item, work_item) && work_item.get_widget(:decision_log).present?
      end

      def update_attributes
        params.slice(*UPDATABLE_ATTRIBUTES)
      end

      def provided_attributes
        params.slice(*UPDATABLE_ATTRIBUTES, :selected_option_content)
      end

      # A provided attribute may be replaced but never cleared; omitted
      # attributes are left untouched
      def blank_attributes
        provided_attributes.select { |_, value| value.blank? }.keys
      end

      def resolution_attributes
        provided_attributes.slice(*RESOLUTION_ATTRIBUTES).keys
      end

      def blank_attributes_error
        format(_("%{attributes} can't be blank"), attributes: human_attribute_names(blank_attributes))
      end

      def resolution_attributes_error
        format(
          _('%{attributes} can only be updated on resolved decisions'),
          attributes: human_attribute_names(resolution_attributes)
        )
      end

      def human_attribute_names(attributes)
        attributes.map { |attribute| decision.class.human_attribute_name(attribute) }.to_sentence
      end

      def resolver_provided?
        update_attributes.key?(:resolved_by_id)
      end

      def valid_resolver?
        resolver.present? && Ability.allowed?(resolver, :read_work_item, work_item)
      end

      def resolver
        User.find_by_id(update_attributes[:resolved_by_id])
      end
      strong_memoize_attr :resolver

      def resolving_note_provided?
        update_attributes.key?(:resolving_note_id)
      end

      def valid_resolving_note?
        note = Note.find_by_id(update_attributes[:resolving_note_id])

        note.present? && Ability.allowed?(current_user, :read_note, note) && decision.resolvable_by_note?(note)
      end

      def options_params
        Array(params[:options]).map do |option_params|
          option_params.to_h.slice(:id, *OPTION_TEXT_ATTRIBUTES, *OPTION_FLAG_ATTRIBUTES)
        end
      end
      strong_memoize_attr :options_params

      def option_ids
        options_params.map { |option_params| option_params[:id].to_i }
      end

      def options_by_id
        decision.options.index_by(&:id)
      end
      strong_memoize_attr :options_by_id

      # selected is a boolean, so false is a valid value and only nil is blank
      def blank_option_attributes
        options_params.flat_map do |option_params|
          option_params.except(:id).select do |attribute, value|
            OPTION_FLAG_ATTRIBUTES.include?(attribute) ? value.nil? : value.blank?
          end.keys
        end.uniq
      end

      def blank_option_attributes_error
        format(
          _("Option %{attributes} can't be blank"),
          attributes: blank_option_attributes.map do |attribute|
            DecisionOption.human_attribute_name(attribute).downcase
          end.to_sentence
        )
      end

      def selecting?
        options_params.any? { |option_params| option_params.key?(:selected) }
      end

      # Evaluated against the state the update would leave behind, so an
      # existing rationale or one sent in the same call both satisfy it
      def rejecting_all_options?
        return false unless selecting?

        none_selected_after_update? && effective_rationale.blank?
      end

      def none_selected_after_update?
        decision.options.none? do |option|
          change = options_params.find { |option_params| option_params[:id].to_i == option.id }
          change&.key?(:selected) ? change[:selected] : option.selected
        end
      end

      def selected_option_content_provided?
        params.key?(:selected_option_content)
      end

      def selected_options
        decision.options.select(&:selected)
      end
      strong_memoize_attr :selected_options

      # One selected option is the decision text, so it is edited in place, as
      # options[].content already allows. Several selected options have no single
      # text to edit, so the content becomes a new selected option and the
      # originals stay as unselected proposals
      def update_selected_option_content!
        content = params[:selected_option_content]

        if selected_options.one?
          selected_options.first.update!(content: content)
        else
          decision.write_in_option!(content)
        end
      end

      def track_event
        ::Gitlab::WorkItems::Instrumentation::TrackingService.track_decision_event(
          event: ::Gitlab::WorkItems::Instrumentation::EventActions::DECISION_UPDATE,
          decision: decision,
          current_user: current_user
        )
      end

      def effective_rationale
        return update_attributes[:resolution_rationale] if update_attributes.key?(:resolution_rationale)

        decision.resolution_rationale
      end
    end
  end
end
