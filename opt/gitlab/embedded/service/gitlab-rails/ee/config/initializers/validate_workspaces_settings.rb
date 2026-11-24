# frozen_string_literal: true

raise "Workspaces host is not set" if Gitlab.config.workspaces.enabled && Gitlab.config.workspaces.host.blank?
