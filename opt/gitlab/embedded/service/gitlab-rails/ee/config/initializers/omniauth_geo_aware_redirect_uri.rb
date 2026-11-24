# frozen_string_literal: true

require 'omniauth_openid_connect'

# Must load after the omniauth_openid_connect gem defines the strategy.
# Prepending to OpenIDConnect also covers subclasses such as
# OmniAuth::Strategies::CellsAwareOpenidConnect (Cells and Geo do not run
# together, so the Geo guard makes this a no-op there).
OmniAuth::Strategies::OpenIDConnect.prepend(OmniAuth::Strategies::GeoAwareRedirectUri)
