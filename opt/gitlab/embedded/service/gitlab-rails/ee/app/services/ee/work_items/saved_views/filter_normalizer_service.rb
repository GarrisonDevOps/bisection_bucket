# frozen_string_literal: true

module EE
  module WorkItems
    module SavedViews
      module FilterNormalizerService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          result = super
          return result unless result.success?

          # Custom fields are already passed as IDs, check if they exist when reading the saved view
          normalize_attribute(:custom_field, :custom_field) { |values| normalize_custom_field_entries(values) }
          normalize_attribute(:iteration_id, :iteration_id) { |value| value }

          normalize_iteration_cadence_id
          normalize_status

          ServiceResponse.success(payload: normalized_filters)
        rescue ArgumentError => e
          ServiceResponse.error(message: e.message)
        end

        private

        # Recognizes `key::*` scoped label wildcards, same as live-list filtering.
        override :label_wildcard?
        def label_wildcard?(value)
          return true if super

          return false unless container.root_ancestor.licensed_feature_available?(:scoped_labels)

          value.to_s.end_with?("#{::Label::SCOPED_LABEL_SEPARATOR}#{::EE::Issuables::LabelFilter::SCOPED_LABEL_WILDCARD}")
        end

        def normalize_custom_field_entries(custom_fields)
          custom_fields.filter_map do |cf|
            normalize_single_custom_field(cf)
          end
        end

        def normalize_single_custom_field(cf)
          # Normalize custom field
          custom_field_id = if cf[:custom_field_id]
                              cf[:custom_field_id]
                            elsif cf[:custom_field_name]
                              find_custom_field_id_by_name(cf[:custom_field_name])
                            end

          return unless custom_field_id

          # Normalize selected options
          selected_option_ids = if cf[:selected_option_ids]
                                  cf[:selected_option_ids]
                                elsif cf[:selected_option_values]
                                  find_option_ids_by_values(custom_field_id, cf[:selected_option_values])
                                end

          return unless selected_option_ids&.any?

          {
            custom_field_id: custom_field_id.to_s,
            selected_option_ids: selected_option_ids.map(&:to_s)
          }
        end

        def find_custom_field_id_by_name(name)
          root_namespace = container.root_ancestor
          descendant_ids = root_namespace.self_and_descendant_ids

          descendant_ids.each do |namespace_id|
            custom_field = ::Issuables::CustomField
                             .of_namespace(namespace_id)
                             .find_by_case_insensitive_name(name)

            return custom_field.id if custom_field
          end

          nil
        end

        def find_option_ids_by_values(custom_field_id, values)
          ::Issuables::CustomFieldSelectOption
            .of_field(custom_field_id)
            .with_case_insensitive_values(values)
            .map(&:id)
        end

        def normalize_iteration_cadence_id
          # Note: input is iteration_cadence_id, output is iteration_cadence_ids (plural)
          return unless filters[:iteration_cadence_id]

          normalized_filters[:iteration_cadence_ids] = filters[:iteration_cadence_id]
        end

        def normalize_status
          return unless filters[:status]

          status_filter = filters[:status]
          status_filter = status_filter[:id] if status_filter.is_a?(Hash) && status_filter[:id]

          # Status can be provided as either an ID or by name. We store the value as an ID regardless, but also the
          # format it was provided in, plus a boolean indicating whether the status is custom or system-defined so
          # the sanitizer can detect mismatches on load (e.g. after enabling/disabling custom statuses).
          if status_filter.is_a?(::WorkItems::Statuses::Status)
            normalized_filters[:status] = {
              id: status_filter.id,
              input_format: :id,
              custom: status_filter.is_a?(::WorkItems::Statuses::Custom::Status)
            }
          elsif status_filter.is_a?(Hash) && status_filter[:name]
            status = find_status_by_name(status_filter[:name])
            if status
              normalized_filters[:status] = {
                id: status.id,
                input_format: :name,
                custom: status.is_a?(::WorkItems::Statuses::Custom::Status)
              }
            end
          end
        end

        def find_status_by_name(name)
          root_namespace = container.root_ancestor

          ::WorkItems::Statuses::Finder.new(
            root_namespace, { 'name' => name },
            current_user: current_user
          ).execute.first
        end
      end
    end
  end
end
