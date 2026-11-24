# frozen_string_literal: true

module EE
  module WorkItems
    module ExportCsvService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      override :header_to_value_hash
      def header_to_value_hash
        super.merge({
          'Weight' => ->(work_item) { widget_value_for(work_item, :weight) }
        })
      end

      override :widget_preloads
      def widget_preloads
        super.concat([:sync_object])
      end
    end
  end
end
