# frozen_string_literal: true

module Search
  module Admin
    class VectorStoragePresenter
      AdapterSection = Struct.new(
        :hidden_class, :in_use, :options, :password_value, :aws_secret_value, :inputs_disabled,
        keyword_init: true
      )

      attr_reader :using_advanced_search, :custom_active, :inputs_disabled

      def initialize(
        using_advanced_search:,
        custom_active:,
        inputs_disabled:,
        selected_adapter_name:,
        existing_adapter_name:,
        adapter_configs:
      )
        @using_advanced_search = using_advanced_search
        @custom_active = custom_active
        @inputs_disabled = inputs_disabled
        @selected_adapter_name = selected_adapter_name
        @existing_adapter_name = existing_adapter_name
        @adapter_configs = adapter_configs
      end

      def advanced_search_configured?
        License.feature_available?(:elastic_search) && Gitlab::CurrentSettings.elasticsearch_indexing?
      end

      def effective_adapter_name
        @selected_adapter_name || 'elasticsearch'
      end

      def adapter_section(adapter)
        config = @adapter_configs.fetch(adapter, {})

        AdapterSection.new(
          hidden_class: hidden_class_for(adapter),
          in_use: @custom_active && @existing_adapter_name == adapter,
          options: normalize_aws(config.fetch('options', {})),
          password_value: config['password_value'],
          aws_secret_value: config['aws_secret_value'],
          inputs_disabled: @inputs_disabled
        )
      end

      private

      def normalize_aws(opts)
        return opts unless opts.key?('aws')

        opts.merge('aws' => Gitlab::Utils.to_boolean(opts['aws']))
      end

      def hidden_class_for(adapter)
        effective_adapter_name == adapter ? '' : 'gl-hidden'
      end
    end
  end
end
