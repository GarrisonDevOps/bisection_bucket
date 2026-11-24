# frozen_string_literal: true

if Gem::Version.new(JsRoutes::VERSION) > Gem::Version.new('2.3.7')
  raise 'New version of js-routes detected, please either update the version for this check, ' \
    'or update this patch'
end

# js-routes derives how nil query parameters are serialized from the Rails version: `?key=` before
# Rails 8.1 and `?key` from 8.1. Pinning the old behavior keeps the committed path helpers identical
# on every Rails version we boot, so `gitlab:js:routes:updated_check` passes during the dual boot.
module Gitlab
  module JsRoutesNilQueryParameterPatch
    protected

    def js_variables
      super.merge('DEPRECATED_NIL_QUERY_PARAMETER_BEHAVIOR' => true)
    end
  end
end

JsRoutes::Instance.prepend(Gitlab::JsRoutesNilQueryParameterPatch)
