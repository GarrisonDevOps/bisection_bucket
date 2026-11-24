# frozen_string_literal: true

begin
  Gitlab::Geo.current_node&.update_clone_url! if Gitlab::Geo.connected? && Gitlab::Geo.primary?
rescue StandardError => e
  warn "WARNING: Unable to check/update clone_url_prefix for Geo: #{e}"
end
