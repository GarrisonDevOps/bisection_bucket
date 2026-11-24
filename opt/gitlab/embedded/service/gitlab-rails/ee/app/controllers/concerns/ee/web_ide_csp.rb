# frozen_string_literal: true

module EE
  module WebIdeCSP
    extend ::Gitlab::Utils::Override

    override :include_web_ide_csp
    def include_web_ide_csp
      super

      return if request.content_security_policy.directives.blank?

      default_src = Array(request.content_security_policy.directives['default-src'] || [])
      request.content_security_policy.directives['connect-src'] ||= default_src
      request.content_security_policy.directives['connect-src'].concat(["#{::Gitlab::AiGateway.url}/"])
    end
  end
end
