# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class TemplateCacheService
      def initialize
        @cache = {}
      end

      def fetch(scan_type, template: 'default', inputs: {})
        inputs = inputs.deep_dup.symbolize_keys.freeze

        (@cache[[scan_type.to_sym, template, inputs]] ||= ci_configuration(scan_type, template, inputs)).deep_dup
      end

      private

      def ci_configuration(scan_type, template, inputs)
        Gitlab::Ci::Config.new(template_content(scan_type, template), inputs: inputs).to_hash
      end

      def template_content(scan_type, template)
        template_finder(scan_type, template).execute.content
      end

      def template_finder(scan_type, template)
        ::TemplateFinder.build(:gitlab_ci_ymls, nil, name: CiAction::Template.scan_template_path(scan_type, template))
      end
    end
  end
end
